# Contribuindo

1. `cargo test` tem de passar sem crates extras.
2. Invariantes novos entram em `docs/INVARIANTES.md` **e** em `tests/`.
3. Não inventar throughput no README.
4. SQL novo precisa de teste de parse + execução.
5. Mudança de layout on-disk sobe `FORMAT_VERSION` em `src/catalog.rs`.
6. Após alterar dependências ou o manifesto, execute `cargo generate-lockfile` e confirme
   `cargo test --all-targets` antes de atualizar o CI.
7. Alterações na ABI C devem manter `tests/ffi_header.c` compilável com C11.
8. Mudanças no motor rodam o teste de modelo em modo estresse
   (`MINIDB_MODEL_STEPS=20000 cargo test --release --test model_based`).
9. Novo decodificador de entrada externa ganha caso em `tests/robustness.rs` e alvo em `fuzz/`.
10. Mudanças na API HTTP atualizam OpenAPI, `docs/HTTP.md` e os clientes
    (valide com `scripts/clients_smoke.sh`).

Detalhes da estratégia de testes: [docs/QUALIDADE.md](docs/QUALIDADE.md).
