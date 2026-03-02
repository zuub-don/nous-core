# Nous Core — development task runner
# Install: cargo install just

default: check

# Run all checks (build, test, clippy, fmt)
check: build test lint fmt-check

# Build workspace
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Run clippy with deny warnings
lint:
    cargo clippy --workspace -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --check

# Auto-format
fmt:
    cargo fmt

# Build in release mode
release:
    cargo build --workspace --release

# Run a specific crate's tests
test-crate crate:
    cargo test -p {{crate}}

# Run nous-engine
run-engine:
    cargo run -p nous-engine

# Run nous-ctl
run-ctl:
    cargo run -p nous-ctl

# Run nous-mcp
run-mcp:
    cargo run -p nous-mcp

# Generate docs
doc:
    cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
    cargo clean

# Watch mode: re-run tests on file changes (requires cargo-watch)
watch:
    cargo watch -x 'test --workspace'
