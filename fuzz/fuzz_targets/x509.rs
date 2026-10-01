#![no_main]
//! Os decodificadores de certificado e de chave (DER/PEM), que recebem bytes de
//! clientes de rede antes da autenticação, nunca entram em pânico.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mini_db::x509::Cert::parse(data);
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(blocks) = mini_db::x509::pem_all(text, "CERTIFICATE") {
            for der in blocks {
                let _ = mini_db::x509::Cert::parse(&der);
            }
        }
        let _ = mini_db::pubkey::PrivateKey::from_pem(text);
    }
});
