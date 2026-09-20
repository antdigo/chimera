use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    if let Some(code) = chimera::job::execution_domain::internal_entry() {
        std::process::exit(code);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(chimera::cli::run(chimera::cli::Cli::parse()))
}
