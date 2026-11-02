.PHONY: all build test install docker clean help

help:
	@echo "Available targets:"
	@echo "  make build    - Compile release binaries (secarbiter & secarbiter-mcp)"
	@echo "  make test     - Run full test suite"
	@echo "  make install  - Install binaries to ~/.local/bin and build Docker sandbox"
	@echo "  make docker   - Build the secarbiter-sandbox Docker image"
	@echo "  make clean    - Clean build artifacts"

build:
	cargo build --release --workspace

test:
	cargo test --workspace

docker:
	docker build -t secarbiter-sandbox:latest -t pentest-sandbox:latest -f docker/executor.Dockerfile docker/

install:
	./install.sh

clean:
	cargo clean
