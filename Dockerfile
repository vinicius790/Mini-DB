FROM rust:1.89-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bins

FROM debian:bookworm-slim
RUN useradd -r -u 10001 minidb && mkdir /data && chown minidb /data
COPY --from=build /src/target/release/minidb /usr/local/bin/minidb
COPY --from=build /src/target/release/minidb-bench /usr/local/bin/minidb-bench
COPY --from=build /src/target/release/minidb-verify /usr/local/bin/minidb-verify
COPY --from=build /src/target/release/minidb-inspect /usr/local/bin/minidb-inspect
USER minidb
# 8080 = HTTP/JSON. O protocolo PostgreSQL (5432) e o TCP de linhas (7432) ficam
# em 127.0.0.1 dentro do contêiner; para publicá-los, defina MINIDB_PG/MINIDB_TCP
# com 0.0.0.0 e MINIDB_TOKEN (ou crie usuários) antes de expor as portas.
EXPOSE 8080
VOLUME ["/data"]
ENV MINIDB_PATH=/data
ENV MINIDB_HTTP=0.0.0.0:8080
ENTRYPOINT ["minidb"]
CMD ["http", "/data", "0.0.0.0:8080"]
