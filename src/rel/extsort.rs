//! Algoritmo de ordenação externa (External Merge Sort) e controle de spill para disco.
//!
//! Quando uma consulta SQL envolve `ORDER BY`, joins ou operações de agregação
//! com volume de linhas que excede a memória configurada (`max_in_memory_rows`),
//! o `ExternalSorter` divide o conjunto em lotes (runs) ordenados em memória,
//! persiste cada lote em arquivos temporários em disco com I/O em buffer (64 KiB),
//! e realiza um K-way merge streaming retornando as linhas ordenadas com consumo
//! de memória constante $O(K)$, garantindo ausência de OOM.

use std::cmp::Ordering;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use crate::error::Result;
use super::exec::cmp_order;
use super::parser::OrderItem;
use super::value::{decode_row, encode_row, Value};

/// Um registro a ser ordenado, contendo a chave de ordenação e a linha projetada correspondente.
#[derive(Clone, Debug)]
pub struct SortEntry {
    pub key: Vec<Value>,
    pub row: Vec<Value>,
}

/// Um lote temporário gravado em disco (Run), com remoção automática via RAII `Drop`.
pub struct TempRun {
    path: PathBuf,
    pub count: usize,
}

impl TempRun {
    pub fn write_run(path: PathBuf, entries: &[SortEntry]) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);

        // Header: quantidade de entradas no run
        writer.write_all(&(entries.len() as u64).to_le_bytes())?;

        for entry in entries {
            let k_bytes = encode_row(&entry.key);
            let r_bytes = encode_row(&entry.row);

            writer.write_all(&(k_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(&k_bytes)?;
            writer.write_all(&(r_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(&r_bytes)?;
        }

        writer.flush()?;
        Ok(Self {
            path,
            count: entries.len(),
        })
    }

    pub fn open_reader(&self) -> Result<RunReader> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        let mut len_buf = [0u8; 8];
        reader.read_exact(&mut len_buf)?;
        let total = u64::from_le_bytes(len_buf) as usize;
        Ok(RunReader {
            reader,
            remaining: total,
        })
    }
}

impl Drop for TempRun {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Leitor sequencial de um lote temporário (Run) com buffer de 64 KiB.
pub struct RunReader {
    reader: BufReader<File>,
    remaining: usize,
}

impl RunReader {
    pub fn next_entry(&mut self) -> Result<Option<SortEntry>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut len_buf = [0u8; 4];
        if self.reader.read_exact(&mut len_buf).is_err() {
            return Ok(None);
        }
        let klen = u32::from_le_bytes(len_buf) as usize;
        let mut kbuf = vec![0u8; klen];
        self.reader.read_exact(&mut kbuf)?;
        let key = decode_row(&kbuf)?;

        self.reader.read_exact(&mut len_buf)?;
        let rlen = u32::from_le_bytes(len_buf) as usize;
        let mut rbuf = vec![0u8; rlen];
        self.reader.read_exact(&mut rbuf)?;
        let row = decode_row(&rbuf)?;

        self.remaining -= 1;
        Ok(Some(SortEntry { key, row }))
    }
}

/// Um arquivo temporário de partição para Grace Hash Join, com limpeza RAII no Drop.
pub struct PartitionRun {
    path: PathBuf,
    pub count: usize,
}

impl PartitionRun {
    pub fn create(path: PathBuf) -> Result<PartitionWriter> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        let writer = BufWriter::with_capacity(64 * 1024, file);
        Ok(PartitionWriter {
            path,
            writer,
            count: 0,
        })
    }

    pub fn open_reader(&self) -> Result<PartitionReader> {
        let file = File::open(&self.path)?;
        let reader = BufReader::with_capacity(64 * 1024, file);
        Ok(PartitionReader { reader })
    }
}

impl Drop for PartitionRun {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Escritor sequencial de partição em disco para Grace Hash Join.
pub struct PartitionWriter {
    path: PathBuf,
    writer: BufWriter<File>,
    count: usize,
}

impl PartitionWriter {
    pub fn write_row(&mut self, row: &[Value]) -> Result<()> {
        let r_bytes = encode_row(row);
        self.writer.write_all(&(r_bytes.len() as u32).to_le_bytes())?;
        self.writer.write_all(&r_bytes)?;
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<PartitionRun> {
        self.writer.flush()?;
        Ok(PartitionRun {
            path: self.path,
            count: self.count,
        })
    }
}

/// Leitor sequencial de partição em disco para Grace Hash Join.
pub struct PartitionReader {
    reader: BufReader<File>,
}

impl PartitionReader {
    pub fn next_row(&mut self) -> Result<Option<Vec<Value>>> {
        let mut len_buf = [0u8; 4];
        if self.reader.read_exact(&mut len_buf).is_err() {
            return Ok(None);
        }
        let rlen = u32::from_le_bytes(len_buf) as usize;
        let mut rbuf = vec![0u8; rlen];
        self.reader.read_exact(&mut rbuf)?;
        let row = decode_row(&rbuf)?;
        Ok(Some(row))
    }
}

/// Ordenador híbrido: opera 100% em memória enquanto o número de linhas couber
/// no limite configurado. Se o volume exceder `max_memory_rows`, faz spill
/// progressivo para runs em disco e executa K-way merge streaming.
pub struct ExternalSorter {
    temp_dir: PathBuf,
    max_memory_rows: usize,
    order_items: Vec<OrderItem>,
    buffer: Vec<SortEntry>,
    runs: Vec<TempRun>,
    run_seq: usize,
    total_rows: usize,
}

impl ExternalSorter {
    pub fn new(temp_dir: PathBuf, max_memory_rows: usize, order_items: Vec<OrderItem>) -> Self {
        Self {
            temp_dir,
            max_memory_rows: max_memory_rows.max(16),
            order_items,
            buffer: Vec::with_capacity(max_memory_rows.min(65536)),
            runs: Vec::new(),
            run_seq: 0,
            total_rows: 0,
        }
    }

    pub fn push(&mut self, key: Vec<Value>, row: Vec<Value>) -> Result<()> {
        self.buffer.push(SortEntry { key, row });
        self.total_rows += 1;

        if self.buffer.len() >= self.max_memory_rows {
            self.flush_run()?;
        }
        Ok(())
    }

    fn flush_run(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let order_items = &self.order_items;
        self.buffer
            .sort_by(|a, b| cmp_order(&a.key, &b.key, order_items));

        self.run_seq += 1;
        let run_path = self.temp_dir.join(format!(
            "minidb_sort_{}_{}.tmp",
            std::process::id(),
            self.run_seq
        ));

        let run = TempRun::write_run(run_path, &self.buffer)?;
        self.runs.push(run);
        self.buffer.clear();
        Ok(())
    }

    pub fn finish(mut self) -> Result<SortIterator> {
        if self.runs.is_empty() {
            let order_items = &self.order_items;
            self.buffer
                .sort_by(|a, b| cmp_order(&a.key, &b.key, order_items));
            Ok(SortIterator::Memory {
                iter: self.buffer.into_iter(),
            })
        } else {
            if !self.buffer.is_empty() {
                self.flush_run()?;
            }

            let mut readers = Vec::with_capacity(self.runs.len());
            let mut heads = Vec::with_capacity(self.runs.len());

            for run in &self.runs {
                let mut reader = run.open_reader()?;
                let head = reader.next_entry()?;
                readers.push(reader);
                heads.push(head);
            }

            Ok(SortIterator::External {
                _runs: self.runs,
                readers,
                heads,
                order_items: self.order_items,
            })
        }
    }
}

/// Iterador sobre o resultado ordenado (em memória ou via K-way merge em disco).
pub enum SortIterator {
    Memory {
        iter: std::vec::IntoIter<SortEntry>,
    },
    External {
        _runs: Vec<TempRun>,
        readers: Vec<RunReader>,
        heads: Vec<Option<SortEntry>>,
        order_items: Vec<OrderItem>,
    },
}

impl SortIterator {
    pub fn next_entry(&mut self) -> Result<Option<SortEntry>> {
        match self {
            Self::Memory { iter } => Ok(iter.next()),
            Self::External {
                readers,
                heads,
                order_items,
                ..
            } => {
                let mut min_idx: Option<usize> = None;
                for (i, head) in heads.iter().enumerate() {
                    if let Some(entry) = head {
                        match min_idx {
                            None => min_idx = Some(i),
                            Some(best) => {
                                let best_entry = heads[best].as_ref().unwrap();
                                if cmp_order(&entry.key, &best_entry.key, order_items)
                                    == Ordering::Less
                                {
                                    min_idx = Some(i);
                                }
                            }
                        }
                    }
                }

                let Some(chosen_run) = min_idx else {
                    return Ok(None);
                };

                let chosen_entry = heads[chosen_run].take().unwrap();
                heads[chosen_run] = readers[chosen_run].next_entry()?;

                Ok(Some(chosen_entry))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_sorter_in_memory() {
        let temp_dir = std::env::temp_dir();
        let items = vec![OrderItem {
            expr: crate::rel::parser::Expr::Col(None, "x".into()),
            desc: false,
            nulls_first: None,
        }];
        let mut sorter = ExternalSorter::new(temp_dir, 100, items);
        for v in [5, 2, 8, 1, 9, 3] {
            sorter
                .push(vec![Value::Int(v)], vec![Value::Int(v * 10)])
                .unwrap();
        }
        let mut iter = sorter.finish().unwrap();
        let mut res = Vec::new();
        while let Some(e) = iter.next_entry().unwrap() {
            res.push(e.key[0].clone());
        }
        assert_eq!(
            res,
            vec![
                Value::Int(1),
                Value::Int(2),
                Value::Int(3),
                Value::Int(5),
                Value::Int(8),
                Value::Int(9)
            ]
        );
    }

    #[test]
    fn test_external_sorter_spill_to_disk() {
        let temp_dir = std::env::temp_dir();
        let items = vec![OrderItem {
            expr: crate::rel::parser::Expr::Col(None, "x".into()),
            desc: false,
            nulls_first: None,
        }];
        let mut sorter = ExternalSorter::new(temp_dir, 5, items);
        let data = vec![23, 12, 99, 1, 45, 67, 3, 10, 8, 15, 2];
        for &v in &data {
            sorter
                .push(vec![Value::Int(v)], vec![Value::Int(v)])
                .unwrap();
        }
        let mut iter = sorter.finish().unwrap();
        let mut res = Vec::new();
        while let Some(e) = iter.next_entry().unwrap() {
            res.push(match e.key[0] {
                Value::Int(n) => n,
                _ => panic!("esperava int"),
            });
        }
        let mut expected = data.clone();
        expected.sort();
        assert_eq!(res, expected);
    }
}
