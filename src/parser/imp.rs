use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

use super::hash::{HashSignature, HashSource, HashType};

#[derive(Debug)]
pub struct ImpSignature<'p> {
    pub name: &'p str,
    pub hash: &'p str,
    pub size: Option<u64>,
    pub min_flevel: Option<u32>,
}

impl<'p> ImpSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
        // - docs: `.imp` uses import-hash records (MD5)
        let parsed = HashSignature::parse(sig)?;

        if parsed.hash_type != HashType::Md5 {
            return Err(anyhow!(
                "Invalid imp signature: expected MD5 import hash (32 hex chars)"
            ));
        }

        let HashSignature {
            name,
            hash,
            source,
            min_flevel,
            ..
        } = parsed;

        let size = match source {
            HashSource::File { size } => size,
            HashSource::Section { .. } => {
                return Err(anyhow!(
                    "Invalid imp signature: expected file-hash format (section hash is not valid for .imp)"
                ));
            }
        };

        Ok(Self {
            name,
            hash,
            size,
            min_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::HashSignature {
        ir::HashSignature {
            name: self.name.to_string(),
            hash: self.hash.to_string(),
            hash_type: ir::HashType::Md5,
            source: ir::HashSource::File { size: self.size },
            min_flevel: self.min_flevel,
        }
    }
}

impl<'p> Display for ImpSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_imp_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_imp_signature() {
        let sig = "d41d8cd98f00b204e9800998ecf8427e:2048:Test.Imp.Signature";
        let parsed = ImpSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "Test.Imp.Signature");
        assert_eq!(parsed.hash, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(parsed.size, Some(2048));
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_imp_with_wildcard_size_and_flevel() {
        let sig = "d41d8cd98f00b204e9800998ecf8427e:*:Test.Imp.Signature:73";
        let parsed = ImpSignature::parse(sig).unwrap();

        assert_eq!(parsed.size, None);
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_imp_rejects_non_md5_hash() {
        let sig = "0059ee2322c3301263c8006fd780d7fe95a30572:2048:Test.Imp.Signature";
        assert!(ImpSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_imp_rejects_section_hash_format() {
        let sig = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Test.Imp.Signature";
        assert!(ImpSignature::parse(sig).is_err());
    }
}
