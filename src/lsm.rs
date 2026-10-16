//! Motor de armazenamento baseado em Log-Structured Merge-tree (LSM-Tree) com filtros Bloom por SSTable.
//!
//! Este módulo provê persistência de alta taxa de escrita e leituras aceleradas em disco.
//! Toda SSTable ([`SsTable`]) gerada durante o flush ou compactação embute um filtro Bloom ([`Bloom`])
//! indexado em memória RAM.
//!
//! ### Aceleração de Verificações de Existência com Filtro Bloom:
//! Em arquiteturas LSM-Tree sem filtro Bloom, uma consulta por chave ausente precisa realizar busca binária
//! e leitura em disco em cada SSTable do diretório. Com o filtro Bloom:
//! 1. **Zero I/O para chaves ausentes**: Se `sstable.bloom.may_contain(key)` retornar `false`, a SSTable é
//!    descartada imediatamente na RAM, evitando qualquer seek ou leitura no arquivo em disco.
//! 2. **Filtro de Faixa**: Chaves fora dos limites `[min_key, max_key]` são descartadas antes mesmo do hash.
//! 3. **Leitura Direcionada**: Acessos ao disco ocorrem exclusivamente quando o Bloom reporta presença provável.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::bloom::Bloom;
use crate::error::{Error, Result};
use crate::wal::{Wal, WalRecord};

/// Tamanho padrão limite da MemTable antes de disparar o flush (64 KiB).
pub const DEFAULT_MEMTABLE_FLUSH_THRESHOLD: usize = 64 * 1024;

/// Magic bytes no rodapé (footer) da SSTable: "MINISST1"
const SSTABLE_MAGIC: [u8; 8] = *b"MINISST1";
/// Tamanho fixo do rodapé (footer): 5 campos u64 (40 bytes) + 8 bytes magic = 48 bytes.
const FOOTER_SIZE: usize = 48;

/// Métrica de observabilidade do motor LSM e eficácia dos filtros Bloom.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LsmMetrics {
    /// Consultas resolvidas com sucesso diretamente na MemTable em memória.
    pub memtable_hits: u64,
    /// Total de verificações realizadas em filtros Bloom de SSTables.
    pub bloom_checks: u64,
    /// Consultas a SSTables evitadas com sucesso pelo filtro Bloom (I/O economizado!).
    pub bloom_negatives: u64,
    /// Consultas onde o filtro Bloom indicou presença provável.
    pub bloom_positives: u64,
    /// Leituras físicas a arquivos SSTable em disco.
    pub disk_reads: u64,
    /// Chaves encontradas no disco após indicação positiva do filtro Bloom.
    pub disk_hits: u64,
    /// Falsos positivos do filtro Bloom (Bloom indicou provável existência, mas chave não estava na SSTable).
    pub bloom_false_positives: u64,
    /// Quantidade de flushes de MemTable para SSTable executados.
    pub flushes: u64,
    /// Quantidade de compactações executadas.
    pub compactions: u64,
}

/// Tabela em memória que armazena pares chave-valor mutáveis ordenados.
/// Valores `None` representam marcadores de exclusão (tombstones).
#[derive(Clone, Debug, Default)]
pub struct MemTable {
    map: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    approx_size_bytes: usize,
}

impl MemTable {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            approx_size_bytes: 0,
        }
    }

    /// Insere ou atualiza uma chave na MemTable.
    pub fn put(&mut self, key: Vec<u8>, val: Vec<u8>) {
        let entry_size = key.len() + val.len() + 16;
        if let Some(old) = self.map.insert(key, Some(val)) {
            let old_size = old.map(|v| v.len()).unwrap_or(0);
            self.approx_size_bytes = self.approx_size_bytes.saturating_sub(old_size);
        }
        self.approx_size_bytes += entry_size;
    }

    /// Grava um tombstone (marca de remoção) para a chave.
    pub fn delete(&mut self, key: Vec<u8>) {
        let entry_size = key.len() + 16;
        if let Some(old) = self.map.insert(key, None) {
            let old_size = old.map(|v| v.len()).unwrap_or(0);
            self.approx_size_bytes = self.approx_size_bytes.saturating_sub(old_size);
        }
        self.approx_size_bytes += entry_size;
    }

    /// Retorna `Some(Some(v))` se presente, `Some(None)` se excluída (tombstone), ou `None` se ausente.
    pub fn get(&self, key: &[u8]) -> Option<Option<&[u8]>> {
        self.map.get(key).map(|opt| opt.as_deref())
    }

    pub fn size_bytes(&self) -> usize {
        self.approx_size_bytes
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Option<Vec<u8>>)> {
        self.map.iter()
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.approx_size_bytes = 0;
    }
}

/// Entrada no índice em memória da SSTable para busca rápida sem varredura completa.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub key: Vec<u8>,
    pub offset: u64,
    pub length: u32,
}

/// Representa uma SSTable imutável em disco associada a um filtro Bloom mantido em RAM.
#[derive(Clone, Debug)]
pub struct SsTable {
    pub id: u64,
    pub file_path: PathBuf,
    pub min_key: Vec<u8>,
    pub max_key: Vec<u8>,
    pub num_entries: u64,
    /// Filtro Bloom residente em RAM contendo todas as chaves gravadas nesta SSTable.
    pub bloom: Bloom,
    /// Índice esparso/denso residente em RAM para localização rápida de blocos/registros.
    pub index: Vec<IndexEntry>,
}

impl SsTable {
    /// Determina rapidamente na memória RAM se a SSTable pode conter a chave especificada.
    /// Retorna `false` imediatamente se a chave estiver fora do intervalo `[min_key, max_key]`
    /// ou se o filtro Bloom descartar a chave.
    ///
    /// Se retornar `false`, a garantia é absoluta: a chave NÃO existe nesta SSTable e
    /// nenhum I/O de disco precisa ser executado.
    #[inline]
    pub fn may_contain(&self, key: &[u8]) -> bool {
        if self.num_entries == 0 || self.min_key.is_empty() {
            return false;
        }
        // 1. Verificação de limites de chaves em RAM (sem I/O)
        if key < self.min_key.as_slice() || key > self.max_key.as_slice() {
            return false;
        }
        // 2. Verificação no filtro Bloom em RAM (sem I/O)
        self.bloom.may_contain(key)
    }

    /// Busca o valor da chave no arquivo da SSTable em disco.
    /// Retorna `Some(Some(valor))` se encontrada, `Some(None)` se tombstone, ou `None` se não encontrada.
    pub fn get(&self, key: &[u8]) -> Result<Option<Option<Vec<u8>>>> {
        if !self.may_contain(key) {
            return Ok(None);
        }

        // Busca binária no índice em RAM
        let pos = match self.index.binary_search_by(|entry| entry.key.as_slice().cmp(key)) {
            Ok(idx) => idx,
            Err(_) => return Ok(None),
        };

        let entry_meta = &self.index[pos];
        let mut file = File::open(&self.file_path)?;
        file.seek(SeekFrom::Start(entry_meta.offset))?;

        let mut buf = vec![0u8; entry_meta.length as usize];
        file.read_exact(&mut buf)?;

        // Formato do registro de dados:
        // [key_len: u32][val_len: i64][key bytes][val bytes (se val_len >= 0)]
        if buf.len() < 12 {
            return Err(Error::Other("registro de SSTable truncado".into()));
        }
        let klen = u32::from_le_bytes(buf[0..4].try_into().map_err(|_| Error::Other("klen inv".into()))?) as usize;
        let vlen = i64::from_le_bytes(buf[4..12].try_into().map_err(|_| Error::Other("vlen inv".into()))?);

        if 12 + klen > buf.len() {
            return Err(Error::Other("registro de SSTable corrompido: klen excede buffer".into()));
        }
        let record_key = &buf[12..12 + klen];
        if record_key != key {
            return Ok(None);
        }

        if vlen < 0 {
            // Tombstone
            Ok(Some(None))
        } else {
            let vlen = vlen as usize;
            if 12 + klen + vlen > buf.len() {
                return Err(Error::Other("registro de SSTable corrompido: vlen excede buffer".into()));
            }
            let val = buf[12 + klen..12 + klen + vlen].to_vec();
            Ok(Some(Some(val)))
        }
    }

    /// Grava uma nova SSTable no disco a partir de um iterador ordenado de pares chave/valor.
    /// Cria o filtro Bloom residente preenchido com todas as chaves processadas.
    pub fn write_new<'a, I>(path: &Path, id: u64, entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (&'a Vec<u8>, &'a Option<Vec<u8>>)>,
    {
        let file_path = path.join(format!("{:08}.sst", id));
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_path)?;
        let mut writer = BufWriter::new(file);

        let mut min_key = Vec::new();
        let mut max_key = Vec::new();
        let mut index = Vec::new();
        let mut bloom = Bloom::new();
        let mut num_entries = 0u64;

        let mut current_offset = 0u64;

        // 1. Bloco de Dados
        for (k, v) in entries {
            if min_key.is_empty() {
                min_key = k.clone();
            }
            max_key = k.clone();

            // Adiciona a chave ao Filtro Bloom da SSTable
            bloom.insert(k);

            let klen = k.len() as u32;
            let vlen = match v {
                Some(val) => val.len() as i64,
                None => -1i64, // Tombstone
            };

            let entry_offset = current_offset;
            writer.write_all(&klen.to_le_bytes())?;
            writer.write_all(&vlen.to_le_bytes())?;
            writer.write_all(k)?;
            let mut record_len = 4 + 8 + k.len() as u32;

            if let Some(val) = v {
                writer.write_all(val)?;
                record_len += val.len() as u32;
            }

            index.push(IndexEntry {
                key: k.clone(),
                offset: entry_offset,
                length: record_len,
            });

            current_offset += record_len as u64;
            num_entries += 1;
        }

        // 2. Bloco de Índice
        let index_offset = current_offset;
        let index_entries_count = index.len() as u64;
        writer.write_all(&index_entries_count.to_le_bytes())?;
        current_offset += 8;

        for entry in &index {
            let klen = entry.key.len() as u32;
            writer.write_all(&klen.to_le_bytes())?;
            writer.write_all(&entry.key)?;
            writer.write_all(&entry.offset.to_le_bytes())?;
            writer.write_all(&entry.length.to_le_bytes())?;
            current_offset += 4 + entry.key.len() as u64 + 8 + 4;
        }
        let index_len = current_offset - index_offset;

        // 3. Bloco do Filtro Bloom
        let filter_offset = current_offset;
        let bloom_bytes = bloom.to_bytes();
        writer.write_all(&bloom_bytes)?;
        let filter_len = bloom_bytes.len() as u64;

        // 4. Rodapé (Footer fixo de 48 bytes)
        writer.write_all(&index_offset.to_le_bytes())?;
        writer.write_all(&index_len.to_le_bytes())?;
        writer.write_all(&filter_offset.to_le_bytes())?;
        writer.write_all(&filter_len.to_le_bytes())?;
        writer.write_all(&num_entries.to_le_bytes())?;
        writer.write_all(&SSTABLE_MAGIC)?;

        writer.flush()?;
        let file = writer.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        file.sync_all()?;

        Ok(Self {
            id,
            file_path,
            min_key,
            max_key,
            num_entries,
            bloom,
            index,
        })
    }

    /// Abre uma SSTable existente em disco, lendo o rodapé, o índice e o filtro Bloom para a memória RAM.
    pub fn open(file_path: PathBuf, id: u64) -> Result<Self> {
        let mut file = File::open(&file_path)?;
        let file_len = file.metadata()?.len();
        if file_len < FOOTER_SIZE as u64 {
            return Err(Error::Other(format!(
                "SSTable {:?} com tamanho insuficiente ({file_len} bytes)",
                file_path
            )));
        }

        // Lê o rodapé
        file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))?;
        let mut footer = [0u8; FOOTER_SIZE];
        file.read_exact(&mut footer)?;

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&footer[40..48]);
        if magic != SSTABLE_MAGIC {
            return Err(Error::Other(format!(
                "Magic inválido no rodapé da SSTable {:?}",
                file_path
            )));
        }

        let index_offset = u64::from_le_bytes(footer[0..8].try_into().map_err(|_| Error::Other("err".into()))?);
        let _index_len = u64::from_le_bytes(footer[8..16].try_into().map_err(|_| Error::Other("err".into()))?);
        let filter_offset = u64::from_le_bytes(footer[16..24].try_into().map_err(|_| Error::Other("err".into()))?);
        let filter_len = u64::from_le_bytes(footer[24..32].try_into().map_err(|_| Error::Other("err".into()))?);
        let num_entries = u64::from_le_bytes(footer[32..40].try_into().map_err(|_| Error::Other("err".into()))?);

        // Lê o Filtro Bloom para a memória RAM
        file.seek(SeekFrom::Start(filter_offset))?;
        let mut bloom_bytes = vec![0u8; filter_len as usize];
        file.read_exact(&mut bloom_bytes)?;
        let bloom = Bloom::from_bytes(&bloom_bytes).ok_or_else(|| {
            Error::Other(format!(
                "Filtro Bloom corrompido na SSTable {:?}",
                file_path
            ))
        })?;

        // Lê o Índice
        file.seek(SeekFrom::Start(index_offset))?;
        let mut count_buf = [0u8; 8];
        file.read_exact(&mut count_buf)?;
        let entry_count = u64::from_le_bytes(count_buf) as usize;

        let mut index = Vec::with_capacity(entry_count);
        let mut min_key = Vec::new();
        let mut max_key = Vec::new();

        for i in 0..entry_count {
            let mut klen_buf = [0u8; 4];
            file.read_exact(&mut klen_buf)?;
            let klen = u32::from_le_bytes(klen_buf) as usize;

            let mut key = vec![0u8; klen];
            file.read_exact(&mut key)?;

            let mut meta_buf = [0u8; 12];
            file.read_exact(&mut meta_buf)?;
            let offset = u64::from_le_bytes(meta_buf[0..8].try_into().map_err(|_| Error::Other("err".into()))?);
            let length = u32::from_le_bytes(meta_buf[8..12].try_into().map_err(|_| Error::Other("err".into()))?);

            if i == 0 {
                min_key = key.clone();
            }
            max_key = key.clone();

            index.push(IndexEntry { key, offset, length });
        }

        Ok(Self {
            id,
            file_path,
            min_key,
            max_key,
            num_entries,
            bloom,
            index,
        })
    }

    /// Itera todos os registros decodificados desta SSTable em ordem crescente de chave.
    pub fn read_all_entries(&self) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
        let mut file = File::open(&self.file_path)?;
        let mut result = Vec::with_capacity(self.index.len());
        for entry in &self.index {
            file.seek(SeekFrom::Start(entry.offset))?;
            let mut buf = vec![0u8; entry.length as usize];
            file.read_exact(&mut buf)?;
            let klen = u32::from_le_bytes(buf[0..4].try_into().map_err(|_| Error::Other("err".into()))?) as usize;
            let vlen = i64::from_le_bytes(buf[4..12].try_into().map_err(|_| Error::Other("err".into()))?);
            let key = buf[12..12 + klen].to_vec();
            let val = if vlen < 0 {
                None
            } else {
                Some(buf[12 + klen..12 + klen + vlen as usize].to_vec())
            };
            result.push((key, val));
        }
        Ok(result)
    }
}

/// Motor de Armazenamento baseado em LSM-Tree com filtros Bloom por SSTable.
pub struct LsmEngine {
    dir: PathBuf,
    wal: Option<Wal>,
    memtable: MemTable,
    immutable_memtables: Vec<MemTable>,
    /// SSTables ordenadas do mais recente (id maior) ao mais antigo (id menor).
    sstables: Vec<SsTable>,
    next_sst_id: u64,
    flush_threshold_bytes: usize,
    metrics: LsmMetrics,
}

impl LsmEngine {
    /// Abre ou inicializa um novo motor LSM-Tree no diretório especificado.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let mut sstables = Vec::new();
        let mut max_id = 0u64;

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("sst") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(id) = stem.parse::<u64>() {
                        max_id = max_id.max(id);
                        let sst = SsTable::open(path, id)?;
                        sstables.push(sst);
                    }
                }
            }
        }

        // Ordena da SSTable mais recente para a mais antiga (ordem de busca no LSM)
        sstables.sort_by(|a, b| b.id.cmp(&a.id));

        // Carrega registros não consolidados do WAL para a MemTable
        let wal_path = dir.join("lsm.wal");
        let mut memtable = MemTable::new();
        let (next_lsn, records) = Wal::read_all(&wal_path)?;
        for record in records {
            match record {
                WalRecord::Insert { key, value, .. } => {
                    memtable.put(key, value);
                }
                WalRecord::Delete { key, .. } => {
                    memtable.delete(key);
                }
                _ => {}
            }
        }
        let wal = Some(Wal::open(&wal_path, next_lsn)?);

        Ok(Self {
            dir,
            wal,
            memtable,
            immutable_memtables: Vec::new(),
            sstables,
            next_sst_id: max_id + 1,
            flush_threshold_bytes: DEFAULT_MEMTABLE_FLUSH_THRESHOLD,
            metrics: LsmMetrics::default(),
        })
    }

    /// Desativa o WAL síncrono para testes ou benchmarking puramente em memória.
    pub fn without_wal(mut self) -> Self {
        self.wal = None;
        self
    }

    /// Define o limite de tamanho em bytes da MemTable para disparo automático de flush.
    pub fn with_flush_threshold(mut self, bytes: usize) -> Self {
        self.flush_threshold_bytes = bytes.max(1024);
        self
    }

    /// Retorna as métricas de operação e eficácia dos filtros Bloom.
    pub fn metrics(&self) -> &LsmMetrics {
        &self.metrics
    }

    /// Quantidade de SSTables ativas gerenciadas pelo motor.
    pub fn sstable_count(&self) -> usize {
        self.sstables.len()
    }

    /// Referência às SSTables ativas em ordem da mais recente à mais antiga.
    pub fn sstables(&self) -> &[SsTable] {
        &self.sstables
    }

    /// Insere ou atualiza um par chave-valor. Se o tamanho da MemTable ultrapassar o limiar,
    /// um flush para SSTable em disco é disparado automaticamente.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if let Some(ref mut wal) = self.wal {
            wal.append(WalRecord::Insert {
                lsn: 0,
                key: key.to_vec(),
                value: value.to_vec(),
            })?;
            wal.sync()?;
        }
        self.memtable.put(key.to_vec(), value.to_vec());
        if self.memtable.size_bytes() >= self.flush_threshold_bytes {
            self.flush()?;
        }
        Ok(())
    }

    /// Remove uma chave gravando um tombstone na MemTable.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if let Some(ref mut wal) = self.wal {
            wal.append(WalRecord::Delete {
                lsn: 0,
                key: key.to_vec(),
            })?;
            wal.sync()?;
        }
        self.memtable.delete(key.to_vec());
        if self.memtable.size_bytes() >= self.flush_threshold_bytes {
            self.flush()?;
        }
        Ok(())
    }

    /// Busca o valor associado à chave.
    ///
    /// O fluxo de busca é acelerado da seguinte forma:
    /// 1. Consulta a MemTable ativa em memória.
    /// 2. Consulta eventuais MemTables imutáveis pendentes em memória.
    /// 3. Percorre as SSTables da mais recente para a mais antiga:
    ///    - Avalia `sstable.bloom.may_contain(key)`: se `false`, descarta a SSTable na RAM.
    ///    - Somente em caso positivo consulta o disco.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // 1. MemTable ativa
        if let Some(opt_val) = self.memtable.get(key) {
            self.metrics.memtable_hits += 1;
            return Ok(opt_val.map(|v| v.to_vec()));
        }

        // 2. MemTables imutáveis
        for imm in self.immutable_memtables.iter().rev() {
            if let Some(opt_val) = imm.get(key) {
                self.metrics.memtable_hits += 1;
                return Ok(opt_val.map(|v| v.to_vec()));
            }
        }

        // 3. SSTables (mais recente primeiro)
        for sst in &self.sstables {
            self.metrics.bloom_checks += 1;

            // Verificação em RAM usando Filtro Bloom e intervalo min/max
            if !sst.may_contain(key) {
                // SUCESSO DO FILTRO BLOOM: I/O evitado inteiramente!
                self.metrics.bloom_negatives += 1;
                continue;
            }

            self.metrics.bloom_positives += 1;
            self.metrics.disk_reads += 1;

            match sst.get(key)? {
                Some(Some(val)) => {
                    self.metrics.disk_hits += 1;
                    return Ok(Some(val));
                }
                Some(None) => {
                    // Tombstone encontrado: chave excluída
                    self.metrics.disk_hits += 1;
                    return Ok(None);
                }
                None => {
                    // Falso positivo do filtro Bloom: o Bloom indicou "talvez", mas a chave não existia
                    self.metrics.bloom_false_positives += 1;
                }
            }
        }

        Ok(None)
    }

    /// Força o flush da MemTable ativa para uma nova SSTable em disco.
    pub fn flush(&mut self) -> Result<Option<u64>> {
        if self.memtable.is_empty() {
            return Ok(None);
        }

        let sst_id = self.next_sst_id;
        self.next_sst_id += 1;

        let sstable = SsTable::write_new(&self.dir, sst_id, self.memtable.iter())?;
        self.sstables.insert(0, sstable);
        self.memtable.clear();
        if let Some(ref mut wal) = self.wal {
            let next = wal.next_lsn();
            wal.truncate_after_checkpoint(next)?;
        }
        self.metrics.flushes += 1;

        Ok(Some(sst_id))
    }

    /// Compacta todas as SSTables ativas em uma única SSTable consolidada.
    ///
    /// Durante a compactação:
    /// - Múltiplas versões da mesma chave são unificadas, preservando apenas a versão mais recente.
    /// - Tombstones antigos são expurgados.
    /// - Um NOVO Filtro Bloom limpo e ideal é gerado contendo estritamente as chaves sobreviventes.
    /// - Arquivos SSTable antigos são removidos do disco.
    pub fn compact(&mut self) -> Result<()> {
        if self.sstables.len() < 2 {
            return Ok(());
        }

        // Despeja memtable ativa se tiver dados pendentes
        if !self.memtable.is_empty() {
            self.flush()?;
        }

        // Coleta todos os registros de todas as SSTables
        // Da mais antiga para a mais recente para que as novas sobrescrevam
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for sst in self.sstables.iter().rev() {
            let entries = sst.read_all_entries()?;
            for (k, v) in entries {
                merged.insert(k, v);
            }
        }

        // Remove tombstones definitivos na consolidação final
        let live_entries: Vec<(Vec<u8>, Option<Vec<u8>>)> = merged
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, Some(val))))
            .collect();

        let new_id = self.next_sst_id;
        self.next_sst_id += 1;

        let iter_refs = live_entries.iter().map(|(k, v)| (k, v));
        let new_sstable = SsTable::write_new(&self.dir, new_id, iter_refs)?;

        // Exclui arquivos antigos
        for old_sst in &self.sstables {
            let _ = fs::remove_file(&old_sst.file_path);
        }

        self.sstables = vec![new_sstable];
        self.metrics.compactions += 1;

        Ok(())
    }

    /// Realiza varredura ordenada por faixa `[start, end)`.
    pub fn scan(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut combined: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();

        // 1. SSTables da mais antiga para a mais recente
        for sst in self.sstables.iter().rev() {
            for (k, v) in sst.read_all_entries()? {
                if k.as_slice() >= start && end.map_or(true, |e| k.as_slice() < e) {
                    combined.insert(k, v);
                }
            }
        }

        // 2. MemTables imutáveis
        for imm in &self.immutable_memtables {
            for (k, v) in imm.iter() {
                if k.as_slice() >= start && end.map_or(true, |e| k.as_slice() < e) {
                    combined.insert(k.clone(), v.clone());
                }
            }
        }

        // 3. MemTable ativa
        for (k, v) in self.memtable.iter() {
            if k.as_slice() >= start && end.map_or(true, |e| k.as_slice() < e) {
                combined.insert(k.clone(), v.clone());
            }
        }

        let result = combined
            .into_iter()
            .filter_map(|(k, opt_v)| opt_v.map(|v| (k, v)))
            .collect();

        Ok(result)
    }

    /// Sincroniza e fecha o motor, descarregando dados pendentes da MemTable.
    pub fn close(&mut self) -> Result<()> {
        if !self.memtable.is_empty() {
            self.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("minidb_lsm_test_{}_{}", label, time));
        let _ = fs::remove_dir_all(&path);
        let _ = fs::create_dir_all(&path);
        path
    }

    #[test]
    fn memtable_crud() {
        let mut mem = MemTable::new();
        assert!(mem.is_empty());

        mem.put(b"k1".to_vec(), b"v1".to_vec());
        assert_eq!(mem.get(b"k1"), Some(Some(&b"v1"[..])));
        assert_eq!(mem.get(b"k2"), None);

        mem.delete(b"k1".to_vec());
        assert_eq!(mem.get(b"k1"), Some(None)); // tombstone
    }

    #[test]
    fn sstable_bloom_filter_eliminates_disk_access() {
        let dir = temp_test_dir("bloom_elimination");

        // Grava 1.000 chaves pares: "key:0000", "key:0002", etc.
        let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> = (0..1000u32)
            .step_by(2)
            .map(|i| {
                (
                    format!("key:{:04}", i).into_bytes(),
                    Some(format!("val:{:04}", i).into_bytes()),
                )
            })
            .collect();

        let sst = SsTable::write_new(&dir, 1, entries.iter().map(|(k, v)| (k, v)))
            .expect("falha ao gravar sstable");

        // Chaves gravadas devem ser identificadas pelo Bloom e recuperadas do disco
        for i in (0..1000u32).step_by(2) {
            let k = format!("key:{:04}", i).into_bytes();
            assert!(sst.may_contain(&k), "bloom deveria conter {}", i);
            let val = sst.get(&k).expect("falha no get");
            assert_eq!(val, Some(Some(format!("val:{:04}", i).into_bytes())));
        }

        // Chaves nunca inseridas devem ser descartadas pelo may_contain (sem I/O)
        let mut negative_pruned = 0;
        let total_absent = 1000u32;
        for i in 0..total_absent {
            let absent = format!("nonexistent:{:04}", i).into_bytes();
            if !sst.may_contain(&absent) {
                negative_pruned += 1;
            }
        }

        // Filtro Bloom deve descartar a vasta maioria (> 95%) das chaves ausentes
        assert!(
            negative_pruned > 950,
            "Bloom deveria ter descartado quase tudo, descartou {negative_pruned} de {total_absent}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lsm_engine_bloom_metrics_verify_zero_io_on_misses() {
        let dir = temp_test_dir("bloom_zero_io");
        let mut engine = LsmEngine::open(&dir)
            .expect("falha ao abrir engine")
            .with_flush_threshold(64 * 1024);

        // Insere 200 chaves e força flush para gerar SSTable 1
        for i in 0..200u32 {
            engine
                .put(
                    format!("user:{:04}", i).as_bytes(),
                    format!("data:{}", i).as_bytes(),
                )
                .expect("put falhou");
        }
        engine.flush().expect("flush falhou");

        // Insere mais 200 chaves e força flush para gerar SSTable 2
        for i in 200..400u32 {
            engine
                .put(
                    format!("user:{:04}", i).as_bytes(),
                    format!("data:{}", i).as_bytes(),
                )
                .expect("put falhou");
        }
        engine.flush().expect("flush falhou");

        assert_eq!(engine.sstable_count(), 2);

        // Consulta 100 chaves existentes
        for i in 0..100u32 {
            let val = engine
                .get(format!("user:{:04}", i).as_bytes())
                .expect("get falhou");
            assert_eq!(val, Some(format!("data:{}", i).into_bytes()));
        }

        let disk_reads_before = engine.metrics().disk_reads;

        // Consulta 200 chaves comprovadamente AUSENTES
        for i in 0..200u32 {
            let absent = format!("absent_key_{:04}", i);
            let val = engine.get(absent.as_bytes()).expect("get falhou");
            assert_eq!(val, None);
        }

        // As chaves ausentes devem ter sido barradas pelos filtros Bloom sem gerar leitura de disco!
        let bloom_negatives = engine.metrics().bloom_negatives;
        let disk_reads_after = engine.metrics().disk_reads;

        assert!(
            bloom_negatives >= 380,
            "Filtro Bloom deveria ter rejeitado quase todas as 400 consultas (2 SSTables * 200 chaves), rejeitou: {bloom_negatives}"
        );

        // As leituras de disco para as 200 chaves ausentes devem ser praticamente zero (falsos positivos < 3%)
        let extra_disk_reads = disk_reads_after - disk_reads_before;
        assert!(
            extra_disk_reads <= 5,
            "Leituras de disco indevidas para chaves ausentes: {extra_disk_reads}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistence_and_reload_restores_bloom_filters() {
        let dir = temp_test_dir("persistence_reload");

        {
            let mut engine = LsmEngine::open(&dir).expect("abertura 1");
            for i in 0..300u32 {
                engine
                    .put(
                        format!("item:{:05}", i).as_bytes(),
                        format!("val:{}", i).as_bytes(),
                    )
                    .expect("put");
            }
            engine.flush().expect("flush 1");

            for i in 300..600u32 {
                engine
                    .put(
                        format!("item:{:05}", i).as_bytes(),
                        format!("val:{}", i).as_bytes(),
                    )
                    .expect("put");
            }
            engine.flush().expect("flush 2");
            engine.close().expect("close");
        }

        // Reabre o motor no mesmo diretório
        {
            let mut engine = LsmEngine::open(&dir).expect("abertura 2");
            assert_eq!(engine.sstable_count(), 2);

            // Verifica se os filtros Bloom foram carregados corretamente do rodapé
            for sst in engine.sstables() {
                assert!(sst.bloom.inserts() > 0, "bloom deve conter inserções restauradas");
            }

            // Consultas normais
            assert_eq!(
                engine.get(b"item:00150").expect("get"),
                Some(b"val:150".to_vec())
            );
            assert_eq!(
                engine.get(b"item:00550").expect("get"),
                Some(b"val:550".to_vec())
            );

            // Chave ausente é rejeitada pelo Bloom restaurado
            let absent = b"item:99999";
            assert_eq!(engine.get(absent).expect("get"), None);
            assert!(engine.metrics().bloom_negatives > 0);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_rebuilds_bloom_filter_for_compacted_sstable() {
        let dir = temp_test_dir("compaction_bloom");
        let mut engine = LsmEngine::open(&dir).expect("abertura");

        // SSTable 1: k1, k2, k3
        engine.put(b"k1", b"v1_old").expect("put");
        engine.put(b"k2", b"v2").expect("put");
        engine.put(b"k3", b"v3").expect("put");
        engine.flush().expect("flush 1");

        // SSTable 2: atualiza k1, deleta k2, insere k4
        engine.put(b"k1", b"v1_new").expect("put");
        engine.delete(b"k2").expect("delete");
        engine.put(b"k4", b"v4").expect("put");
        engine.flush().expect("flush 2");

        assert_eq!(engine.sstable_count(), 2);

        // Executa a compactação
        engine.compact().expect("compactação falhou");

        assert_eq!(engine.sstable_count(), 1);
        let compacted_sst = &engine.sstables()[0];

        // O novo filtro Bloom deve conter k1, k3 e k4
        assert!(compacted_sst.bloom.may_contain(b"k1"));
        assert!(compacted_sst.bloom.may_contain(b"k3"));
        assert!(compacted_sst.bloom.may_contain(b"k4"));

        // O valor atualizado deve ser v1_new
        assert_eq!(engine.get(b"k1").expect("get"), Some(b"v1_new".to_vec()));
        // k2 foi removido
        assert_eq!(engine.get(b"k2").expect("get"), None);
        assert_eq!(engine.get(b"k3").expect("get"), Some(b"v3".to_vec()));
        assert_eq!(engine.get(b"k4").expect("get"), Some(b"v4".to_vec()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_across_memtable_and_sstables() {
        let dir = temp_test_dir("scan_lsm");
        let mut engine = LsmEngine::open(&dir).expect("abertura");

        engine.put(b"a", b"1").expect("put");
        engine.put(b"b", b"2").expect("put");
        engine.flush().expect("flush 1");

        engine.put(b"c", b"3").expect("put");
        engine.put(b"d", b"4").expect("put");
        engine.flush().expect("flush 2");

        // Fica na MemTable
        engine.put(b"e", b"5").expect("put");

        let rows = engine.scan(b"b", Some(b"e")).expect("scan");
        assert_eq!(
            rows,
            vec![
                (b"b".to_vec(), b"2".to_vec()),
                (b"c".to_vec(), b"3".to_vec()),
                (b"d".to_vec(), b"4".to_vec()),
            ]
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_crash_recovery_restores_unflushed_memtable() {
        let dir = temp_test_dir("wal_crash_recovery");
        {
            let mut engine = LsmEngine::open(&dir).expect("abertura");
            engine.put(b"key_wal1", b"val_wal1").expect("put");
            engine.put(b"key_wal2", b"val_wal2").expect("put");
            engine.delete(b"key_wal1").expect("delete");
            engine.put(b"key_wal3", b"val_wal3").expect("put");
            // Não executa flush: simula crash do processo fechando o engine
        }

        // Reabre o motor: deve restaurar a MemTable a partir do lsm.wal
        {
            let mut engine = LsmEngine::open(&dir).expect("reabertura");
            assert_eq!(engine.sstable_count(), 0, "não deve haver SSTables ainda");
            assert_eq!(engine.get(b"key_wal1").expect("get"), None, "key1 foi deletada no WAL");
            assert_eq!(engine.get(b"key_wal2").expect("get"), Some(b"val_wal2".to_vec()));
            assert_eq!(engine.get(b"key_wal3").expect("get"), Some(b"val_wal3".to_vec()));

            // Agora realiza flush persistindo em SSTable e limpando o WAL
            engine.flush().expect("flush");
            assert_eq!(engine.sstable_count(), 1);
        }

        // Reabre após flush: dados continuam íntegros vindos da SSTable
        {
            let mut engine = LsmEngine::open(&dir).expect("reabertura pos-flush");
            assert_eq!(engine.sstable_count(), 1);
            assert_eq!(engine.get(b"key_wal2").expect("get"), Some(b"val_wal2".to_vec()));
            assert_eq!(engine.get(b"key_wal3").expect("get"), Some(b"val_wal3".to_vec()));
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
