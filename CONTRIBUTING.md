# Contributing to Nous Core

## Development Setup

```bash
# Prerequisites: Rust 1.80+, just (cargo install just)
git clone https://github.com/nous-sec/nous-core.git
cd nous-core
just check
```

## Workflow

1. Create a branch from `main`
2. Make small, focused changes
3. Ensure `just check` passes (build + test + clippy + fmt)
4. Open a PR with a clear description

## Code Standards

- All public items must have doc comments
- New logic must include tests (success, failure, edge cases)
- No `.unwrap()` in library code
- Use `thiserror` for library errors, `anyhow` for binary errors
- Keep functions under 5 parameters; use config structs for more
- Follow existing patterns in the codebase

## Architecture Changes

Significant changes require an RFC in `rfcs/`. Discuss in an issue first.

## Commit Messages

Use clear, descriptive messages. No commented-out code or debug statements.
