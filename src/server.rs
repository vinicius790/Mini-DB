//! Servidor TCP linha-orientado (um comando por linha, UTF-8).

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cmd;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::http::{reserve_connection, ConnectionGuard};

const MAX_COMMAND_BYTES: usize = 64 * 1024;
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

pub fn serve(db: Arc<Mutex<Db>>, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::Server(e.to_string()))?;
    eprintln!("minidb listen {addr}");
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|e| Error::Server(e.to_string()))?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        if !reserve_connection(&active) {
            let _ = writeln!(stream, "ERR server busy");
            continue;
        }
        let db = Arc::clone(&db);
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let _connection = ConnectionGuard(active);
            if let Err(e) = handle_client(db, stream) {
                eprintln!("client: {e}");
            }
        });
    }
    Ok(())
}

fn handle_client(db: Arc<Mutex<Db>>, stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    writeln!(writer, "minidb 0.5 ready")?;
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
        if cmd_line.eq_ignore_ascii_case("QUIT") || cmd_line.eq_ignore_ascii_case("EXIT") {
            writeln!(writer, "OK bye")?;
            break;
        }
        let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
        match cmd::apply(&mut guard, cmd_line) {
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
    use super::{read_command_line, CommandLine, MAX_COMMAND_BYTES};
    use std::io::Cursor;

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
