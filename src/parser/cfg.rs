use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct CfgSignature<'p> {
    pub raw: &'p str,
    pub domain: &'p str,
    pub flags: &'p str,
    pub min_flevel: u32,
    pub max_flevel: u32,
}

impl<'p> CfgSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures (`*.cfg` is metadata/config, not a scan signature body)
        // - observed record format in daily.cfg: `<DOMAIN>:<HEXFLAGS>:<MINFL>:<MAXFL>`
        let raw = sig.trim_end_matches(['\r', '\n']);
        if raw.trim().is_empty() {
            return Err(anyhow!("Invalid cfg record: empty line"));
        }

        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 4 {
            return Err(anyhow!(
                "Invalid cfg record: expected 4 fields (`DOMAIN:FLAGS:MINFL:MAXFL`)"
            ));
        }

        let domain = parts[0];
        let flags = parts[1];
        let min_flevel = parts[2]
            .parse::<u32>()
            .map_err(|_| anyhow!("Invalid cfg record: malformed MinFL field (expected numeric)"))?;
        let max_flevel = parts[3]
            .parse::<u32>()
            .map_err(|_| anyhow!("Invalid cfg record: malformed MaxFL field (expected numeric)"))?;

        if domain.is_empty() {
            return Err(anyhow!("Invalid cfg record: empty domain field"));
        }
        if !flags.starts_with("0x") || flags.len() <= 2 {
            return Err(anyhow!(
                "Invalid cfg record: malformed flags field (expected 0x-prefixed hex)"
            ));
        }
        if !flags[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "Invalid cfg record: malformed flags field (expected hex digits)"
            ));
        }
        if min_flevel > max_flevel {
            return Err(anyhow!("Invalid cfg record: MinFL must be <= MaxFL"));
        }

        Ok(Self {
            raw,
            domain,
            flags,
            min_flevel,
            max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::CfgSignature {
        ir::CfgSignature {
            raw: self.raw.to_string(),
            domain: self.domain.to_string(),
            flags: self.flags.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for CfgSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_cfg_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_cfg_record() {
        let sig = "DOCUMENT:0x5:11:13";
        let parsed = CfgSignature::parse(sig).unwrap();

        assert_eq!(parsed.raw, sig);
        assert_eq!(parsed.domain, "DOCUMENT");
        assert_eq!(parsed.flags, "0x5");
        assert_eq!(parsed.min_flevel, 11);
        assert_eq!(parsed.max_flevel, 13);
    }

    #[test]
    fn parse_cfg_rejects_non_hex_flags() {
        assert!(CfgSignature::parse("DOCUMENT:0xz:11:13").is_err());
    }

    #[test]
    fn parse_cfg_rejects_non_numeric_flevels() {
        assert!(CfgSignature::parse("DOCUMENT:0x5:x:13").is_err());
        assert!(CfgSignature::parse("DOCUMENT:0x5:11:y").is_err());
    }

    #[test]
    fn parse_cfg_rejects_descending_flevel_range() {
        assert!(CfgSignature::parse("DOCUMENT:0x5:14:13").is_err());
    }
}
