mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use sig2yar::{
    parser::{
        hash::HashSignature, idb::IdbSignature, logical::LogicalSignature, ndb::NdbSignature,
        DbType,
    },
    yara,
};

fn main() -> Result<()> {
    let args = Args::parse();

    match args.db_type {
        DbType::Hash => {
            let sig = HashSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_hash_signature(&ir));
        }
        DbType::Logical => {
            let sig = LogicalSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            let rule = yara::lower_logical_signature(&ir)?;
            println!("{}", rule);
        }
        DbType::Ndb => {
            let sig = NdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ndb_signature(&ir));
        }
        DbType::Idb => {
            let sig = IdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_idb_signature(&ir));
        }
    };

    Ok(())
}
