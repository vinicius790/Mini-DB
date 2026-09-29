/** Cliente HTTP fetch para Mini-DB (Node 18+ / browser). */
export class MiniDbClient {
  constructor(private base = "http://127.0.0.1:8080") {}

  private async req(method: string, path: string, body?: unknown) {
    const res = await fetch(this.base + path, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const ct = res.headers.get("content-type") || "";
    if (!res.ok) {
      const raw = await res.text();
      let message = raw;
      if (ct.includes("application/json")) {
        try {
          const detail = JSON.parse(raw) as { error?: unknown } | null;
          if (typeof detail?.error === "string") message = detail.error;
        } catch {
          // Keep the raw response body when a server error is not valid JSON.
        }
      }
      throw new Error(`Mini-DB HTTP ${res.status}: ${message}`);
    }
    if (ct.includes("application/json")) return res.json();
    return res.text();
  }

  health() {
    return this.req("GET", "/health");
  }
  put(key: string, value: string, ttlMs?: number) {
    return this.req("PUT", "/v1/kv", ttlMs === undefined ? { key, value } : { key, value, ttl_ms: ttlMs });
  }
  putBytes(key: Uint8Array, value: Uint8Array) {
    return this.req("PUT", "/v1/kv", {
      key_hex: this.toHex(key),
      value_hex: this.toHex(value),
    });
  }
  get(key: string) {
    return this.req("GET", `/v1/kv?key=${encodeURIComponent(key)}`);
  }
  delete(key: string) {
    return this.req("DELETE", `/v1/kv?key=${encodeURIComponent(key)}`);
  }
  async scan(options: {
    start?: string;
    end?: string;
    after?: string;
    limit?: number;
    prefix?: string;
  } = {}): Promise<Array<{ key: string; value: string; key_hex: string; value_hex: string }>> {
    const query = new URLSearchParams();
    if (options.prefix !== undefined) query.set("prefix", options.prefix);
    if (options.start !== undefined) query.set("start", options.start);
    if (options.end !== undefined) query.set("end", options.end);
    if (options.after !== undefined) query.set("after", options.after);
    if (options.limit !== undefined) query.set("limit", String(options.limit));
    const queryString = query.toString();
    const suffix = queryString.length > 0 ? `?${queryString}` : "";
    const response = (await this.req("GET", `/v1/scan${suffix}`)) as {
      rows: Array<{ key: string; value: string; key_hex: string; value_hex: string }>;
    };
    return response.rows;
  }
  async getBytes(key: Uint8Array): Promise<Uint8Array | null> {
    const response = await this.req(
      "GET",
      `/v1/kv?key_hex=${encodeURIComponent(this.toHex(key))}`,
    );
    const valueHex = response.value_hex as string | null | undefined;
    return valueHex == null ? null : this.fromHex(valueHex);
  }
  deleteBytes(key: Uint8Array) {
    return this.req(
      "DELETE",
      `/v1/kv?key_hex=${encodeURIComponent(this.toHex(key))}`,
    );
  }
  async scanBytes(options: {
    start?: Uint8Array;
    end?: Uint8Array;
    after?: Uint8Array;
    limit?: number;
  } = {}): Promise<Array<{ key: Uint8Array; value: Uint8Array }>> {
    const query = new URLSearchParams();
    if (options.start !== undefined) query.set("start_hex", this.toHex(options.start));
    if (options.end !== undefined) query.set("end_hex", this.toHex(options.end));
    if (options.after !== undefined) query.set("after_hex", this.toHex(options.after));
    if (options.limit !== undefined) query.set("limit", String(options.limit));
    const queryString = query.toString();
    const suffix = queryString.length > 0 ? `?${queryString}` : "";
    const response = (await this.req("GET", `/v1/scan${suffix}`)) as {
      rows: Array<{ key_hex: string; value_hex: string }>;
    };
    return response.rows.map((row) => ({
      key: this.fromHex(row.key_hex),
      value: this.fromHex(row.value_hex),
    }));
  }
  async count(options: { start?: string; end?: string; prefix?: string } = {}): Promise<number> {
    const query = new URLSearchParams(
      Object.entries(options).filter((entry): entry is [string, string] => entry[1] !== undefined),
    ).toString();
    const response = (await this.req("GET", `/v1/count${query ? `?${query}` : ""}`)) as { count: number };
    return response.count;
  }
  /** Lote atômico de puts/deletes (todas ou nenhuma sobrevivem a um crash). */
  batch(
    ops: Array<{ op: "put"; key: string; value: string; ttl_ms?: number } | { op: "delete"; key: string }>,
  ) {
    return this.req("POST", "/v1/batch", { ops });
  }
  ttl(key: string): Promise<{ state: "missing" | "persistent" | "expires"; ttl_ms: number | null }> {
    return this.req("GET", `/v1/ttl?key=${encodeURIComponent(key)}`);
  }
  /** Define TTL; `null` remove a expiração. */
  async expire(key: string, ttlMs: number | null): Promise<boolean> {
    return ((await this.req("POST", "/v1/expire", { key, ttl_ms: ttlMs })) as { updated: boolean }).updated;
  }
  async purge(): Promise<number> {
    return ((await this.req("POST", "/v1/purge", {})) as { purged: number }).purged;
  }
  pages() {
    return this.req("GET", "/v1/pages");
  }
  sql(sql: string) {
    return this.req("POST", "/v1/sql", { sql });
  }
  metrics(): Promise<string> {
    return this.req("GET", "/metrics") as Promise<string>;
  }

  private toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  private fromHex(hex: string): Uint8Array {
    if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
      throw new Error("Mini-DB returned invalid hexadecimal data");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }
}
