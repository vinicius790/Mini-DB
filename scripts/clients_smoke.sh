#!/usr/bin/env bash
# Sobe o servidor HTTP e exercita os clientes Python e TypeScript de ponta a ponta.
# Requer python3; o cliente TS é testado quando `node` (18+) e `tsc` existem.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${MINIDB_SMOKE_PORT:-18080}"
DATA="$(mktemp -d)"
cargo build -q --manifest-path "$ROOT/Cargo.toml" --bin minidb
"$ROOT/target/debug/minidb" http "$DATA" "127.0.0.1:$PORT" 2>/dev/null &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DATA"' EXIT
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep 0.1; done

PYTHONPATH="$ROOT/clients" python3 - "$PORT" <<'PY'
import sys
from minidb_client import MiniDbClient
c = MiniDbClient(f"http://127.0.0.1:{sys.argv[1]}")
c.batch([{"op": "put", "key": "py:1", "value": "a"}, {"op": "put", "key": "py:2", "value": "b", "ttl_ms": 60000}])
c.put_bytes(b"py:\x00", b"\xff")
assert c.count(prefix="py:") == 3
assert c.ttl("py:2")["state"] == "expires" and c.expire("py:2", None)
assert c.get_bytes(b"py:\x00") == b"\xff"
assert [r["key"] for r in c.scan(prefix="py:", limit=2)] == ["py:\x00", "py:1"]
assert c.sql("SELECT COUNT(*) FROM kv WHERE key LIKE 'py:%'")["count"] == 3
assert c.pages()["height"] >= 1 and c.purge() == 0
print("python client ok")
PY

if command -v node >/dev/null && command -v tsc >/dev/null; then
  OUT="$(mktemp -d)"
  tsc --target es2022 --module es2022 --moduleResolution bundler --strict --outDir "$OUT" "$ROOT/clients/minidb_client.ts"
  cat > "$OUT/smoke.mjs" <<JS
import { MiniDbClient } from "./minidb_client.js";
const c = new MiniDbClient("http://127.0.0.1:$PORT");
await c.batch([{ op: "put", key: "ts:1", value: "x", ttl_ms: 60000 }, { op: "delete", key: "py:1" }]);
if ((await c.count({ prefix: "ts:" })) !== 1) throw new Error("count");
if ((await c.ttl("ts:1")).state !== "expires") throw new Error("ttl");
const bytes = await c.getBytes(new TextEncoder().encode("py:\u0000"));
if (!bytes || bytes[0] !== 0xff) throw new Error("bytes");
if ((await c.scan({ prefix: "py:" })).length !== 2) throw new Error("scan");
console.log("typescript client ok");
JS
  node "$OUT/smoke.mjs"
  rm -rf "$OUT"
fi
