.PHONY: test fmt lint doc ci stress smoke bench fuzz http docker

test:
	cargo test --all-targets --locked
	cargo test --doc

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

ci: fmt lint doc test

stress:
	MINIDB_MODEL_STEPS=20000 cargo test --release --test model_based

smoke:
	bash scripts/clients_smoke.sh

bench:
	cargo run --release --bin minidb-bench -- 20000

fuzz:
	cd fuzz && cargo +nightly fuzz run sql_parser -- -max_total_time=60

http:
	cargo run --bin minidb -- http ./data 127.0.0.1:8080

docker:
	docker build -t minidb:1.3.0 .
