# Fixtures PKI (somente teste)

Cadeias RSA e EC (raiz, intermediária, servidor e cliente) geradas com OpenSSL,
usadas por `tests/sql_v10.rs` (TLS/mTLS) e pelos testes unitários de `src/pubkey.rs`
(`sig*.hex` são vetores de assinatura, não chaves).

- **Todas as chaves privadas aqui são públicas e descartáveis.** Nunca as use fora
  dos testes; scanners de segredo vão apontá-las e isso é esperado.
- Assuntos: `O=Teste RSA`/`O=Teste EC`, servidor `CN=127.0.0.1`, cliente `CN=ana`.
- Validade: 2026-09-30 a 2036-09-27. Depois disso `x509::verify_chain` recusa os
  certificados e os testes de TLS falham: gere um conjunto novo com `openssl`
  (raiz → intermediária → servidor/cliente, RSA 2048 e P-256) e substitua os arquivos.
