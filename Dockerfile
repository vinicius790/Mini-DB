FROM rust:1.89-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bins

FROM debian:bookworm-slim
RUN useradd -r -u 10001 minidb
COPY --from=build /src/target/release/minidb /usr/local/bin/minidb
COPY --from=build /src/target/release/minidb-bench /usr/local/bin/minidb-bench
USER minidb
EXPOSE 8080 7432
VOLUME ["/data"]
ENV MINIDB_PATH=/data
ENV MINIDB_HTTP=0.0.0.0:8080
ENTRYPOINT ["minidb"]
CMD ["http", "/data", "0.0.0.0:8080"]
