mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use sig2yar::{
    parser::{
        cbc::CbcSignature, cdb::CdbSignature, crb::CrbSignature, ftm::FtmSignature,
        hash::HashSignature, idb::IdbSignature, logical::LogicalSignature, ndb::NdbSignature,
        pdb::PdbSignature, wdb::WdbSignature, DbType,
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
        DbType::Cbc => {
            let sig = CbcSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_cbc_signature(&ir));
        }
        DbType::Cdb => {
            let sig = CdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_cdb_signature(&ir));
        }
        DbType::Crb => {
            let sig = CrbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_crb_signature(&ir));
        }
        DbType::Pdb => {
            let sig = PdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_pdb_signature(&ir));
        }
        DbType::Wdb => {
            let sig = WdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_wdb_signature(&ir));
        }
        DbType::Ftm => {
            let sig = FtmSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ftm_signature(&ir));
        }
    };

    Ok(())
}
