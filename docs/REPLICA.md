# Réplica por WAL shipping

> Para replicação **contínua** (primário → réplicas por streaming), veja
> [MOTOR-0.5.md](MOTOR-0.5.md#3-replicação-srcreplicationrs). Este módulo cobre só a
> cópia fria de arquivos.

`mini_db::replica::ship_snapshot(src, dst)` copia `data.mdb` + `wal.log`.
`open_standby(dst)` reabre e o recover aplica o log.

O shipping adquire o lock do primário, executa checkpoint e fecha o banco antes
da cópia. Se o primário já estiver aberto por outro processo ou handle, a operação
falha em vez de produzir um snapshot potencialmente inconsistente. O destino recebe
cada arquivo por cópia temporária e rename.

Isso é warm standby, não cluster. Sem eleição, sem lag metric além do LSN
da meta. Serve para:

- backup consistente a frio (feche ou checkpoint no primário antes)
- teste de recover em outro diretório
- drill de desastre

Para alta disponibilidade use a replicação contínua (`replication.rs`: streaming
autenticado e cifrado, semi-síncrona, promoção manual com época e fencing; veja
[MOTOR-0.6.md](MOTOR-0.6.md)). `ship_snapshot` não abre bancos criptografados nem copia
`data.mdb.key`: para esses, use `minidb backup`.
