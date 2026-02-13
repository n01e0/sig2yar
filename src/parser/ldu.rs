use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct LduSignature<'p> {
    pub raw: &'p str,
    pub signature_name: &'p str,
}

impl<'p> LduSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures (`*.ldb *.ldu; *.idb: Logical Signatures`)
        // - docs: same page notes `*u` extensions are loaded in PUA mode
        let raw = sig.trim_end_matches(['\r', '\n']);

        if raw.trim().is_empty() {
            return Err(anyhow!(
                "Invalid ldu signature: malformed record (empty signature)"
            ));
        }

        let (signature_name, _) = raw.split_once(';').ok_or_else(|| {
            anyhow!("Invalid ldu signature: malformed logical record (missing ';' delimiter)")
        })?;

        if signature_name.is_empty() {
            return Err(anyhow!(
                "Invalid ldu signature: malformed logical record (empty signature name)"
            ));
        }

        Ok(Self {
            raw,
            signature_name,
        })
    }

    pub fn to_ir(&self) -> ir::LduSignature {
        ir::LduSignature {
            raw: self.raw.to_string(),
            signature_name: self.signature_name.to_string(),
        }
    }
}

impl<'p> Display for LduSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_ldu_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_ldu_record() {
        let sig = "PUA.CVE_2012_0198;Engine:51-255,Target:3;0&1;636C6173;72756E";
        let parsed = LduSignature::parse(sig).unwrap();

        assert_eq!(parsed.raw, sig);
        assert_eq!(parsed.signature_name, "PUA.CVE_2012_0198");
    }

    #[test]
    fn parse_ldu_trims_trailing_newline() {
        let sig = "PUA.Phishing.Bank;Target:3;0;62616e6b\r\n";
        let parsed = LduSignature::parse(sig).unwrap();

        assert_eq!(parsed.raw, "PUA.Phishing.Bank;Target:3;0;62616e6b");
    }

    #[test]
    fn parse_ldu_rejects_empty_record() {
        assert!(LduSignature::parse("   \n").is_err());
    }

    #[test]
    fn parse_ldu_rejects_missing_logical_delimiter() {
        assert!(LduSignature::parse("PUA.CVE_2012_0198").is_err());
    }

    #[test]
    fn parse_ldu_rejects_empty_signature_name() {
        assert!(LduSignature::parse(";Target:3;0;4141").is_err());
    }
}
