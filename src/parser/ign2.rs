use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

use super::ign::validate_md5;

#[derive(Debug)]
pub struct Ign2Signature<'p> {
    pub raw: &'p str,
    pub signature_name: &'p str,
    pub md5: Option<&'p str>,
    pub legacy_prefix_1: Option<&'p str>,
    pub legacy_prefix_2: Option<&'p str>,
}

impl<'p> Ign2Signature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures/AllowLists (`.ign2`: `SignatureName[:md5(entry)]`)
        // - source: libclamav/readdb.c:2721-2821 (`cli_loadign` handles both .ign/.ign2; token count 1..3)
        let raw = sig.trim_end_matches(['\r', '\n']);

        if raw.trim().is_empty() {
            return Err(anyhow!(
                "Invalid ign2 signature: malformed record (empty signature name)"
            ));
        }

        let tokens: Vec<&str> = raw.split(':').collect();
        if tokens.len() > 3 {
            return Err(anyhow!(
                "Invalid ign2 signature: malformed record (expected 1..3 ':'-separated fields)"
            ));
        }

        let (signature_name, md5, legacy_prefix_1, legacy_prefix_2) = match tokens.len() {
            1 => (tokens[0], None, None, None),
            2 => {
                validate_md5(tokens[1], "ign2")?;
                (tokens[0], Some(tokens[1]), None, None)
            }
            3 => (tokens[2], None, Some(tokens[0]), Some(tokens[1])),
            _ => unreachable!(),
        };

        if signature_name.is_empty() {
            return Err(anyhow!(
                "Invalid ign2 signature: malformed record (empty signature name)"
            ));
        }

        Ok(Self {
            raw,
            signature_name,
            md5,
            legacy_prefix_1,
            legacy_prefix_2,
        })
    }

    pub fn to_ir(&self) -> ir::Ign2Signature {
        ir::Ign2Signature {
            raw: self.raw.to_string(),
            signature_name: self.signature_name.to_string(),
            md5: self.md5.map(|v| v.to_string()),
            legacy_prefix_1: self.legacy_prefix_1.map(|v| v.to_string()),
            legacy_prefix_2: self.legacy_prefix_2.map(|v| v.to_string()),
        }
    }
}

impl<'p> Display for Ign2Signature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_ign2_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ign2_name_only_record() {
        let sig = "Eicar-Test-Signature";
        let parsed = Ign2Signature::parse(sig).unwrap();

        assert_eq!(parsed.signature_name, "Eicar-Test-Signature");
        assert_eq!(parsed.md5, None);
        assert_eq!(parsed.legacy_prefix_1, None);
        assert_eq!(parsed.legacy_prefix_2, None);
    }

    #[test]
    fn parse_ign2_name_and_md5_record() {
        let sig = "Eicar-Test-Signature:bc356bae4c42f19a3de16e333ba3569c";
        let parsed = Ign2Signature::parse(sig).unwrap();

        assert_eq!(parsed.signature_name, "Eicar-Test-Signature");
        assert_eq!(parsed.md5, Some("bc356bae4c42f19a3de16e333ba3569c"));
    }

    #[test]
    fn parse_ign2_legacy_three_token_record() {
        let sig = "legacy-repo:legacy-id:Eicar-Test-Signature";
        let parsed = Ign2Signature::parse(sig).unwrap();

        assert_eq!(parsed.signature_name, "Eicar-Test-Signature");
        assert_eq!(parsed.md5, None);
        assert_eq!(parsed.legacy_prefix_1, Some("legacy-repo"));
        assert_eq!(parsed.legacy_prefix_2, Some("legacy-id"));
    }

    #[test]
    fn parse_ign2_rejects_empty_signature_name() {
        assert!(Ign2Signature::parse(":bc356bae4c42f19a3de16e333ba3569c").is_err());
        assert!(Ign2Signature::parse("legacy-repo:legacy-id:").is_err());
    }

    #[test]
    fn parse_ign2_rejects_invalid_md5() {
        assert!(Ign2Signature::parse("Eicar-Test-Signature:1234").is_err());
        assert!(
            Ign2Signature::parse("Eicar-Test-Signature:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err()
        );
    }

    #[test]
    fn parse_ign2_rejects_too_many_tokens() {
        assert!(Ign2Signature::parse("a:b:c:d").is_err());
    }
}
