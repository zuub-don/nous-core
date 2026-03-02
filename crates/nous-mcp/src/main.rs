use anyhow::Result;

fn main() -> Result<()> {
    // TODO: Start MCP server over stdio, expose observe/act/query/configure tools
    println!("nous-mcp v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
