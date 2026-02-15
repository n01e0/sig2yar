use anyhow::Result;
use std::fmt::Display;

use crate::{ir, yara};

use super::ndb::NdbSignature;

#[derive(Debug)]
pub struct NduSignature<'p> {
    pub name: &'p str,
    pub target_type: &'p str,
    pub offset: &'p str,
    pub body: &'p str,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

impl<'p> NduSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
        // - docs: manual/Signatures (`*.ndb`/`*.ndu` use extended signature record format)
        let parsed = NdbSignature::parse(sig)?;

        Ok(Self {
            name: parsed.name,
            target_type: parsed.target_type,
            offset: parsed.offset,
            body: parsed.body,
            min_flevel: parsed.min_flevel,
            max_flevel: parsed.max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::NduSignature {
        ir::NduSignature {
            name: self.name.to_string(),
            target_type: self.target_type.to_string(),
            offset: self.offset.to_string(),
            body: self.body.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for NduSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_ndu_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_ndu_signature() {
        let sig = "PUA.Win.Tool.PsyBNC-1:6:*:707379424e430025732573257300533d002a00533d2573007372632f705f7365727665722e63007365";
        let parsed = NduSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "PUA.Win.Tool.PsyBNC-1");
        assert_eq!(parsed.target_type, "6");
        assert_eq!(parsed.offset, "*");
        assert_eq!(
            parsed.body,
            "707379424e430025732573257300533d002a00533d2573007372632f705f7365727665722e63007365"
        );
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_ndu_with_flevel_suffix() {
        let sig = "PUA.Win.Packer.YodaProt-1:1:EP+0:e803000000eb01??bb55000000e803000000eb01??e88e000000e803000000eb01??e881000000e803000000eb01??e8b7000000e803000000eb01??e8aa000000e803000000eb01??83fb55e803000000eb01??752d:18";
        let parsed = NduSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "PUA.Win.Packer.YodaProt-1");
        assert_eq!(parsed.target_type, "1");
        assert_eq!(parsed.offset, "EP+0");
        assert_eq!(parsed.min_flevel, Some(18));
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_ndu_with_colon_inside_body() {
        let sig = "PUA.Win.Trojan.Example-1:0:*:AA:BB:73";
        let parsed = NduSignature::parse(sig).unwrap();

        assert_eq!(parsed.body, "AA:BB");
        assert_eq!(parsed.min_flevel, Some(73));
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_ndu_rejects_missing_body() {
        assert!(NduSignature::parse("PUA.Win.Trojan.Example-1:0:*").is_err());
    }
}
