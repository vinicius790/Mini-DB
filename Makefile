.PHONY: test fmt lint ci bench http docker

test:
	cargo test --all-targets --locked
	cargo test --doc

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

ci: fmt lint test

bench:
	cargo run --release --bin minidb-bench -- 2000

http:
	cargo run --bin minidb -- http ./data 127.0.0.1:8080

docker:
	docker build -t minidb:0.5.0 .
