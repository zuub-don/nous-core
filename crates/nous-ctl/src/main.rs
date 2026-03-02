use anyhow::Result;

fn main() -> Result<()> {
    // TODO: Parse CLI args, connect to nous-engine, start TUI or CLI mode
    println!("nous-ctl v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
