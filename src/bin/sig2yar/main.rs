mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use sig2yar::parser::{hash::HashSignature, logical::LogicalSignature, DbType};

fn main() -> Result<()> {
    let args = Args::parse();

    match args.db_type {
        DbType::Hash => {
            let sig = HashSignature::parse(&args.signature)?;
            println!("{}", sig);
        }
        DbType::Logical => {
            let sig = LogicalSignature::parse(&args.signature)?;
            println!("{}", sig);
        }
    };

    Ok(())
}
