# Installation

## Prerequisites

- **Rust** 1.80 or later (MSRV)
- **Protobuf compiler** (`protoc`) — required for gRPC code generation
- **just** (optional) — task runner for convenience commands

## Build from Source

```bash
# Clone the repository
git clone https://github.com/nous-core/nous-core.git
cd nous-core

# Build all crates
cargo build --workspace --release
```

Release binaries are placed in `target/release/`:

```
target/release/nous-engine
target/release/nous-mcp
target/release/nous-ctl
```

## Feature Flags

| Feature | Crate | Description |
|---------|-------|-------------|
| `persistence` | `nous-engine` | Enables PostgreSQL event persistence via sqlx |

To build with persistence support:

```bash
cargo build --workspace --release --features persistence
```

## Verify Installation

```bash
# Check that the binaries run
./target/release/nous-engine --help
./target/release/nous-ctl help
./target/release/nous-mcp  # Reads stdin — Ctrl+C to exit

# Run the test suite
cargo test --workspace

# Run all checks (build, test, clippy, format)
just check
```

## Install just

`just` is a command runner used by this project:

```bash
cargo install just
```

See the [justfile recipes](../configuration/nous-engine.md) for all available commands.
