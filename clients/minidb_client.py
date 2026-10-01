"""Cliente HTTP de referência para o Mini-DB, apenas com a biblioteca padrão."""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request


class MiniDbClient:
    """Com `token`, envia `Authorization: Bearer`; com `username`/`password`, `Basic`."""

    def __init__(
        self,
        base: str = "http://127.0.0.1:8080",
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self.base = base.rstrip("/")
        self._headers = {"Content-Type": "application/json"}
        if username is not None:
            raw = f"{username}:{password or ''}".encode()
            self._headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        elif token is not None:
            self._headers["Authorization"] = f"Bearer {token}"

    def _req(self, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers=self._headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read().decode()
                if resp.headers.get_content_type() == "application/json":
                    return json.loads(raw)
                return raw
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                message = raw
            else:
                message = payload.get("error", raw) if isinstance(payload, dict) else raw
            raise RuntimeError(f"Mini-DB HTTP {error.code}: {message}") from error

    def health(self):
        return self._req("GET", "/health")

    def put(self, key: str, value: str, ttl_ms: int | None = None):
        body = {"key": key, "value": value}
        if ttl_ms is not None:
            body["ttl_ms"] = ttl_ms
        return self._req("PUT", "/v1/kv", body)

    def put_bytes(self, key: bytes, value: bytes):
        return self._req(
            "PUT",
            "/v1/kv",
            {"key_hex": key.hex(), "value_hex": value.hex()},
        )

    def get(self, key: str):
        q = urllib.parse.urlencode({"key": key})
        return self._req("GET", f"/v1/kv?{q}")

    def scan(
        self,
        start: str | None = None,
        end: str | None = None,
        after: str | None = None,
        limit: int | None = None,
        prefix: str | None = None,
    ):
        params = {}
        if prefix is not None:
            params["prefix"] = prefix
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        if after is not None:
            params["after"] = after
        if limit is not None:
            params["limit"] = str(limit)
        q = urllib.parse.urlencode(params)
        return self._req("GET", f"/v1/scan?{q}" if q else "/v1/scan")["rows"]

    def get_bytes(self, key: bytes) -> bytes | None:
        q = urllib.parse.urlencode({"key_hex": key.hex()})
        response = self._req("GET", f"/v1/kv?{q}")
        value_hex = response.get("value_hex")
        return None if value_hex is None else bytes.fromhex(value_hex)

    def delete(self, key: str):
        q = urllib.parse.urlencode({"key": key})
        return self._req("DELETE", f"/v1/kv?{q}")

    def delete_bytes(self, key: bytes):
        q = urllib.parse.urlencode({"key_hex": key.hex()})
        return self._req("DELETE", f"/v1/kv?{q}")

    def scan_bytes(
        self,
        start: bytes | None = None,
        end: bytes | None = None,
        after: bytes | None = None,
        limit: int | None = None,
    ) -> list[tuple[bytes, bytes]]:
        params = {}
        if start is not None:
            params["start_hex"] = start.hex()
        if end is not None:
            params["end_hex"] = end.hex()
        if after is not None:
            params["after_hex"] = after.hex()
        if limit is not None:
            params["limit"] = str(limit)
        q = urllib.parse.urlencode(params)
        response = self._req("GET", f"/v1/scan?{q}" if q else "/v1/scan")
        return [
            (bytes.fromhex(row["key_hex"]), bytes.fromhex(row["value_hex"]))
            for row in response["rows"]
        ]

    def count(self, start: str | None = None, end: str | None = None, prefix: str | None = None) -> int:
        params = {k: v for k, v in {"start": start, "end": end, "prefix": prefix}.items() if v is not None}
        q = urllib.parse.urlencode(params)
        return self._req("GET", f"/v1/count?{q}" if q else "/v1/count")["count"]

    def batch(self, ops: list[dict]):
        """Lote atômico: [{"op": "put", "key": ..., "value": ..., "ttl_ms"?: ...}, {"op": "delete", "key": ...}]."""
        return self._req("POST", "/v1/batch", {"ops": ops})

    def ttl(self, key: str):
        q = urllib.parse.urlencode({"key": key})
        return self._req("GET", f"/v1/ttl?{q}")

    def expire(self, key: str, ttl_ms: int | None) -> bool:
        """Define TTL; ttl_ms=None remove a expiração."""
        return self._req("POST", "/v1/expire", {"key": key, "ttl_ms": ttl_ms})["updated"]

    def purge(self) -> int:
        return self._req("POST", "/v1/purge", {})["purged"]

    def pages(self):
        return self._req("GET", "/v1/pages")

    def sql(self, sql: str, params: list | None = None):
        """Executa SQL; `params` (null/bool/número/texto) preenche `?`, `?N` e `$N`."""
        body = {"sql": sql}
        if params is not None:
            body["params"] = params
        return self._req("POST", "/v1/sql", body)

    def metrics(self) -> str:
        return self._req("GET", "/metrics")


if __name__ == "__main__":
    c = MiniDbClient()
    print(c.health())
