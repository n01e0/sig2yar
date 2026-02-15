mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use sig2yar::{
    parser::{
        cbc::CbcSignature, cdb::CdbSignature, crb::CrbSignature, fp::FpSignature,
        ftm::FtmSignature, hash::HashSignature, hdu::HduSignature, hsu::HsuSignature,
        idb::IdbSignature, ign::IgnSignature, ign2::Ign2Signature, ldu::LduSignature,
        logical::LogicalSignature, mdu::MduSignature, msu::MsuSignature, ndb::NdbSignature,
        ndu::NduSignature, pdb::PdbSignature, sfp::SfpSignature, wdb::WdbSignature, DbType,
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
        DbType::Hdu => {
            let sig = HduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_hdu_signature(&ir));
        }
        DbType::Hsu => {
            let sig = HsuSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_hsu_signature(&ir));
        }
        DbType::Ldu => {
            let sig = LduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ldu_signature(&ir));
        }
        DbType::Mdu => {
            let sig = MduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_mdu_signature(&ir));
        }
        DbType::Msu => {
            let sig = MsuSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_msu_signature(&ir));
        }
        DbType::Ndb => {
            let sig = NdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ndb_signature(&ir));
        }
        DbType::Ndu => {
            let sig = NduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ndu_signature(&ir));
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
        DbType::Fp => {
            let sig = FpSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_fp_signature(&ir));
        }
        DbType::Sfp => {
            let sig = SfpSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_sfp_signature(&ir));
        }
        DbType::Ign => {
            let sig = IgnSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ign_signature(&ir));
        }
        DbType::Ign2 => {
            let sig = Ign2Signature::parse(&args.signature)?;
            let ir = sig.to_ir();
            println!("{}", yara::render_ign2_signature(&ir));
        }
    };

    Ok(())
}
