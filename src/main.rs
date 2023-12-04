mod args;
mod parser;

use args::Args;
use parser::HashSignature;
use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = Args::parse();

    let sig = HashSignature::parse(&args.signature)?;
    println!("{}", sig);
        
    Ok(())
}
