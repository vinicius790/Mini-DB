//! Servidor TCP linha-orientado (um comando por linha, UTF-8).

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use crate::cmd;
use crate::config::NetOptions;
use crate::error::{Error, Result};
use crate::http::{reserve_connection, ConnectionGuard};
use crate::mvcc::SharedDb;

/// Uma linha cabe um valor máximo com folga para o comando e a chave.
const MAX_COMMAND_BYTES: usize = crate::page::MAX_VALUE_LEN + crate::page::MAX_KEY_LEN + 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(300);

enum CommandLine {
    Eof,
    Line(String),
    TooLong,
}

fn read_command_line(reader: &mut impl BufRead) -> io::Result<CommandLine> {
    let mut bytes = Vec::with_capacity(MAX_COMMAND_BYTES.min(1024));
    loop {
        let (consumed, newline) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(CommandLine::Eof);
                }
                break;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(available.len(), |index| index + 1);
            if bytes.len().saturating_add(consumed) > MAX_COMMAND_BYTES {
                return Ok(CommandLine::TooLong);
            }
            bytes.extend_from_slice(&available[..consumed]);
            (consumed, newline.is_some())
        };
        reader.consume(consumed);
        if newline {
            break;
        }
    }
    let line = String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(CommandLine::Line(line))
}

/// Servidor TCP com as opções padrão (sem token, 1024 conexões).
pub fn serve(db: SharedDb, addr: &str) -> Result<()> {
    serve_with(db, addr, NetOptions::default())
}

/// Servidor TCP. Cada conexão roda em sua thread; leituras de conexões
/// diferentes acontecem em paralelo.
pub fn serve_with(db: SharedDb, addr: &str, opts: NetOptions) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::Server(e.to_string()))?;
    eprintln!("minidb listen {addr}");
    let active = Arc::new(AtomicUsize::new(0));
    let opts = Arc::new(opts);
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|e| Error::Server(e.to_string()))?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        if !reserve_connection(&active, opts.max_connections) {
            let _ = writeln!(stream, "ERR server busy");
            continue;
        }
        let db = db.clone();
        // Criado aqui: se a thread não nascer, o guarda cai junto com o fechamento.
        let connection = ConnectionGuard(Arc::clone(&active));
        let opts = Arc::clone(&opts);
        spawn_connection(move || {
            let _connection = connection;
            if let Err(e) = handle_client(&db, stream, &opts) {
                eprintln!("client: {e}");
            }
        });
    }
    Ok(())
}

/// Thread por conexão com pilha grande: o parser SQL e o motor de regex são recursivos.
pub(crate) fn spawn_connection(f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().stack_size(64 << 20).spawn(f) {
        eprintln!("falha ao criar thread de conexão: {e}");
    }
}

/// Linha de requisição HTTP (`MÉTODO alvo HTTP/1.x`, três palavras), como a que um
/// navegador manda ao abrir esta porta. Um comando com mais palavras não é uma.
fn is_http_request_line(line: &str) -> bool {
    let mut words = line.split_whitespace();
    let method = words.next().unwrap_or_default();
    let version = words.nth(1).unwrap_or_default();
    let known_method = matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
    );
    known_method && words.next().is_none() && matches!(version, "HTTP/1.1" | "HTTP/1.0")
}

fn handle_client(db: &SharedDb, stream: TcpStream, opts: &NetOptions) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    writeln!(writer, "minidb 1.3 ready")?;
    let mut session = db.session();
    let mut authenticated = opts.token.is_none() && !session.auth_required()?;
    // Entrou em modo aberto: se alguém criar o primeiro usuário, volta a exigir login.
    let mut open_mode = authenticated;
    loop {
        let line = match read_command_line(&mut reader)? {
            CommandLine::Eof => break,
            CommandLine::Line(line) => line,
            CommandLine::TooLong => {
                writeln!(writer, "ERR comando muito grande")?;
                break;
            }
        };
        let cmd_line = line.trim();
        if cmd_line.is_empty() {
            continue;
        }
        // Um navegador (página qualquer) pode abrir esta porta e mandar um POST:
        // a linha de requisição HTTP encerra a conexão antes do corpo.
        if is_http_request_line(cmd_line) {
            writeln!(writer, "ERR protocolo HTTP não é suportado nesta porta")?;
            break;
        }
        if cmd_line.eq_ignore_ascii_case("QUIT") || cmd_line.eq_ignore_ascii_case("EXIT") {
            writeln!(writer, "OK bye")?;
            break;
        }
        if open_mode {
            match session.auth_required() {
                Ok(true) => {
                    open_mode = false;
                    authenticated = false;
                }
                Ok(false) => {}
                // Falha passageira (réplica ressincronizando): responde e mantém a conexão.
                Err(e) => {
                    writeln!(writer, "ERR {e}")?;
                    continue;
                }
            }
        }
        if !authenticated {
            let credentials = cmd_line
                .strip_prefix("AUTH ")
                .or_else(|| cmd_line.strip_prefix("auth "));
            match credentials {
                Some(rest) => {
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    let ok = match (parts.as_slice(), &opts.token) {
                        ([token], Some(expected)) => {
                            crate::crypto::constant_time_eq(token.as_bytes(), expected.as_bytes())
                        }
                        ([user, password], _) => session.login(user, password).is_ok(),
                        _ => false,
                    };
                    if !ok {
                        writeln!(writer, "ERR credenciais inválidas")?;
                        break;
                    }
                    authenticated = true;
                    writeln!(writer, "OK authenticated")?;
                }
                None => writeln!(
                    writer,
                    "ERR autenticação exigida: AUTH <usuário> <senha>{}",
                    if opts.token.is_some() {
                        " ou AUTH <token>"
                    } else {
                        ""
                    }
                )?,
            }
            continue;
        }
        // Já autenticado por token: `AUTH usuário senha` assume um principal.
        if let Some(rest) = cmd_line
            .strip_prefix("AUTH ")
            .or_else(|| cmd_line.strip_prefix("auth "))
        {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match parts.as_slice() {
                [user, password] => match session.login(user, password) {
                    Ok(()) => writeln!(writer, "OK authenticated {user}")?,
                    Err(e) => writeln!(writer, "ERR {e}")?,
                },
                _ => writeln!(writer, "ERR uso: AUTH <usuário> <senha>")?,
            }
            continue;
        }
        match cmd::apply(&mut session, cmd_line) {
            Ok(msg) => {
                write!(writer, "{msg}")?;
                if !msg.ends_with('\n') {
                    writeln!(writer)?;
                }
            }
            Err(e) => writeln!(writer, "ERR {e}")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_http_request_line, read_command_line, CommandLine, MAX_COMMAND_BYTES};
    use std::io::Cursor;

    #[test]
    fn only_a_real_http_request_line_is_refused() {
        assert!(is_http_request_line("POST /v1/sql HTTP/1.1"));
        assert!(is_http_request_line("GET / HTTP/1.0"));
        // Comandos válidos cujo valor termina em ` HTTP/1.1` seguem valendo.
        assert!(!is_http_request_line("PUT req:1 GET /index.html HTTP/1.1"));
        assert!(!is_http_request_line("SET k HTTP/1.1"));
        assert!(!is_http_request_line("GET key"));
    }

    #[test]
    fn command_line_limit_is_enforced_while_reading() {
        let exact = vec![b'x'; MAX_COMMAND_BYTES - 1];
        let mut exact_with_newline = exact;
        exact_with_newline.push(b'\n');
        assert!(matches!(
            read_command_line(&mut Cursor::new(exact_with_newline)).unwrap(),
            CommandLine::Line(line) if line.len() == MAX_COMMAND_BYTES
        ));

        let oversized = vec![b'x'; MAX_COMMAND_BYTES + 1];
        assert!(matches!(
            read_command_line(&mut Cursor::new(oversized)).unwrap(),
            CommandLine::TooLong
        ));
    }

    #[test]
    fn partial_command_at_eof_is_returned_once() {
        assert!(matches!(
            read_command_line(&mut Cursor::new(b"GET key".as_slice())).unwrap(),
            CommandLine::Line(line) if line == "GET key"
        ));
    }
}
