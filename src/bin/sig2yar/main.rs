mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use sig2yar::{
    parser::{
        cbc::CbcSignature, cdb::CdbSignature, cfg::CfgSignature, crb::CrbSignature,
        fp::FpSignature, ftm::FtmSignature, hash::HashSignature, hdu::HduSignature,
        hsu::HsuSignature, idb::IdbSignature, ign::IgnSignature, ign2::Ign2Signature,
        imp::ImpSignature, info::InfoSignature, ldu::LduSignature, logical::LogicalSignature,
        mdu::MduSignature, msu::MsuSignature, ndb::NdbSignature, ndu::NduSignature,
        pdb::PdbSignature, sfp::SfpSignature, wdb::WdbSignature, DbType,
    },
    yara,
};

fn replace_false_tokens(expr: &str) -> (String, bool) {
    let mut out = String::with_capacity(expr.len());
    let mut tok = String::new();
    let mut replaced = false;

    let flush = |out: &mut String, tok: &mut String, replaced: &mut bool| {
        if tok.is_empty() {
            return;
        }
        if tok == "false" {
            out.push_str("true");
            *replaced = true;
        } else {
            out.push_str(tok);
        }
        tok.clear();
    };

    for ch in expr.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            tok.push(ch);
        } else {
            flush(&mut out, &mut tok, &mut replaced);
            out.push(ch);
        }
    }
    flush(&mut out, &mut tok, &mut replaced);

    (out, replaced)
}

fn seems_unconditional_true(expr: &str) -> bool {
    let lowered = expr.to_ascii_lowercase();
    !lowered.contains('$')
        && !lowered.contains("filesize")
        && !lowered.contains("pe.")
        && !lowered.contains("elf.")
        && !lowered.contains("math.")
        && !lowered.contains("hash.")
        && !lowered.contains("for any")
        && !lowered.contains("for all")
}

fn relax_logical_rule(mut rule: yara::YaraRule) -> yara::YaraRule {
    let (candidate, replaced) = replace_false_tokens(&rule.condition);
    if !replaced {
        return rule;
    }

    if seems_unconditional_true(&candidate) {
        rule.meta.push(yara::YaraMeta::Entry {
            key: "clamav_relaxed".to_string(),
            value: "requested_but_blocked_unconditional_true".to_string(),
        });
        return rule;
    }

    rule.condition = candidate;
    rule.meta.push(yara::YaraMeta::Entry {
        key: "clamav_relaxed".to_string(),
        value: "drop_strict_false_tokens".to_string(),
    });
    rule
}

fn render_rule(args: Args) -> Result<String> {
    let rendered = match args.db_type {
        DbType::Hash => {
            let sig = HashSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_hash_signature(&ir)
        }
        DbType::Imp => {
            let sig = ImpSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_imp_signature(&ir)
        }
        DbType::Logical => {
            let sig = LogicalSignature::parse(&args.signature)?;
            let ir = sig.to_ir();

            let linked_ndb: Vec<_> = args
                .ndb_context
                .iter()
                .map(|raw| NdbSignature::parse(raw).map(|sig| sig.to_ir()))
                .collect::<Result<_>>()?;

            let rule = if linked_ndb.is_empty() {
                yara::lower_logical_signature(&ir)?
            } else {
                yara::lower_logical_signature_with_ndb_context(&ir, &linked_ndb)?
            };

            let rule = if args.relax_strict_false {
                relax_logical_rule(rule)
            } else {
                rule
            };

            rule.to_string()
        }
        DbType::Hdu => {
            let sig = HduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_hdu_signature(&ir)
        }
        DbType::Hsu => {
            let sig = HsuSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_hsu_signature(&ir)
        }
        DbType::Ldu => {
            let sig = LduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_ldu_signature(&ir)
        }
        DbType::Mdu => {
            let sig = MduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_mdu_signature(&ir)
        }
        DbType::Msu => {
            let sig = MsuSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_msu_signature(&ir)
        }
        DbType::Ndb => {
            let sig = NdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_ndb_signature(&ir)
        }
        DbType::Ndu => {
            let sig = NduSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_ndu_signature(&ir)
        }
        DbType::Idb => {
            let sig = IdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_idb_signature(&ir)
        }
        DbType::Cbc => {
            let sig = CbcSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_cbc_signature(&ir)
        }
        DbType::Cdb => {
            let sig = CdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_cdb_signature(&ir)
        }
        DbType::Cfg => {
            let sig = CfgSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_cfg_signature(&ir)
        }
        DbType::Crb => {
            let sig = CrbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_crb_signature(&ir)
        }
        DbType::Pdb => {
            let sig = PdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_pdb_signature(&ir)
        }
        DbType::Wdb => {
            let sig = WdbSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_wdb_signature(&ir)
        }
        DbType::Ftm => {
            let sig = FtmSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_ftm_signature(&ir)
        }
        DbType::Fp => {
            let sig = FpSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_fp_signature(&ir)
        }
        DbType::Sfp => {
            let sig = SfpSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_sfp_signature(&ir)
        }
        DbType::Ign => {
            let sig = IgnSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_ign_signature(&ir)
        }
        DbType::Ign2 => {
            let sig = Ign2Signature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_ign2_signature(&ir)
        }
        DbType::Info => {
            let sig = InfoSignature::parse(&args.signature)?;
            let ir = sig.to_ir();
            yara::render_info_signature(&ir)
        }
    };

    Ok(rendered)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let rendered = render_rule(args)?;
    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_macro_without_ndb_context_stays_strict_false() {
        let args = Args {
            db_type: DbType::Logical,
            signature: "Foo.Bar-1;Target:1;0&1;616161;${6-7}12$".to_string(),
            ndb_context: Vec::new(),
            relax_strict_false: false,
        };

        let out = render_rule(args).expect("render failed");
        assert!(out.contains("macro-group `$12$` semantics depend on CLI_OFF_MACRO"));
        assert!(out.contains("($s0 and false)"));
    }

    #[test]
    fn logical_macro_with_ndb_context_links_member() {
        let args = Args {
            db_type: DbType::Logical,
            signature: "Foo.Bar-1;Target:1;0&1;616161;${6-7}12$".to_string(),
            ndb_context: vec!["D1:0:$12:626262".to_string()],
            relax_strict_false: false,
        };

        let out = render_rule(args).expect("render failed");
        assert!(out.contains("$m1_0 = { 62 62 62 }"));
        assert!(out.contains("macro-group `$12$` resolved via linked ndb members [D1]"));
        assert!(out.contains("@m1_0[j] >= @s0[i] + 6"));
        assert!(!out.contains("($s0 and false)"));
    }

    #[test]
    fn logical_with_invalid_ndb_context_returns_error() {
        let args = Args {
            db_type: DbType::Logical,
            signature: "Foo.Bar-1;Target:1;0&1;616161;${6-7}12$".to_string(),
            ndb_context: vec!["not-an-ndb-line".to_string()],
            relax_strict_false: false,
        };

        assert!(render_rule(args).is_err());
    }

    #[test]
    fn logical_relax_strict_false_replaces_false_tokens() {
        let args = Args {
            db_type: DbType::Logical,
            signature: "Foo.Bar-1;Target:1;0&1;616161;${6-7}12$".to_string(),
            ndb_context: Vec::new(),
            relax_strict_false: true,
        };

        let out = render_rule(args).expect("render failed");
        assert!(out.contains("clamav_relaxed = \"drop_strict_false_tokens\""));
        assert!(out.contains("($s0 and true)"));
        assert!(!out.contains("($s0 and false)"));
    }
}
