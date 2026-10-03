#![no_main]
//! O motor de regex nunca entra em pânico: nem ao compilar o padrão, nem ao casar.
//! A primeira linha da entrada é o padrão; o resto, o texto.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let (pattern, text) = input.split_once('\n').unwrap_or((input, ""));
    // Texto curto: a busca é recursiva e a pilha do fuzzer é a padrão.
    let text: String = text.chars().take(256).collect();
    if let Ok(re) = mini_db::rel::regex::Regex::new(pattern, "") {
        let _ = re.is_match(&text);
    }
});
