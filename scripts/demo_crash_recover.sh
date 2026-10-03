#!/usr/bin/env bash
# Demonstra recuperação real: grava via shell, mata o processo com SIGKILL
# (sem close/checkpoint) e reabre o banco, que refaz o WAL.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/minidb-crash-demo.XXXXXX")"

echo "== build =="
cargo build -q --manifest-path "$ROOT/Cargo.toml" --bin minidb
BIN="$ROOT/target/debug/minidb"

echo "== escrita + kill -9 (sem checkpoint) =="
{ printf 'PUT hero alucard\nPUT castle dracula\n'; sleep 5; } | "$BIN" shell "$DATA" &
PID=$!
sleep 1
kill -9 "$PID"
wait "$PID" 2>/dev/null || true
echo "wal.log: $(wc -c < "$DATA/wal.log") bytes (operações ainda não publicadas em data.mdb)"

echo "== reabertura com recover =="
# Os dados confirmados antes do kill -9 precisam voltar; senão o script falha.
hero="$("$BIN" exec "$DATA" GET hero)"
castle="$("$BIN" exec "$DATA" GET castle)"
[ "$hero" = "alucard" ] || { echo "FALHA: hero='$hero' (esperado alucard)"; exit 1; }
[ "$castle" = "dracula" ] || { echo "FALHA: castle='$castle' (esperado dracula)"; exit 1; }
"$BIN" exec "$DATA" SCAN a z
"$BIN" exec "$DATA" VERIFY
rm -rf "$DATA"
echo "ok — recuperação confirmada"
