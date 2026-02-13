use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

use super::hash::{HashSignature, HashSource, HashType};

#[derive(Debug)]
pub struct FpSignature<'p> {
    pub name: &'p str,
    pub hash: &'p str,
    pub hash_type: HashType,
    pub size: Option<u64>,
    pub min_flevel: Option<u32>,
}

impl<'p> FpSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures/AllowLists (`.fp` uses MD5 file hash signature format)
        // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
        let parsed = HashSignature::parse(sig)?;

        if parsed.hash_type != HashType::Md5 {
            return Err(anyhow!(
                "Invalid fp signature: expected MD5 hash (32 hex chars)"
            ));
        }

        let HashSignature {
            name,
            hash,
            hash_type,
            source,
            min_flevel,
        } = parsed;

        let size = match source {
            HashSource::File { size } => size,
            HashSource::Section { .. } => {
                return Err(anyhow!(
                    "Invalid fp signature: expected file-hash format (section hash is not valid for .fp)"
                ));
            }
        };

        Ok(Self {
            name,
            hash,
            hash_type,
            size,
            min_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::FpSignature {
        ir::FpSignature {
            name: self.name.to_string(),
            hash: self.hash.to_string(),
            hash_type: match self.hash_type {
                HashType::Md5 => ir::HashType::Md5,
                HashType::Sha1 => ir::HashType::Sha1,
                HashType::Sha256 => ir::HashType::Sha256,
            },
            size: self.size,
            min_flevel: self.min_flevel,
        }
    }
}

impl<'p> Display for FpSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_fp_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_fp_signature() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
        let parsed = FpSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "Eicar-Test-Signature");
        assert_eq!(parsed.hash, "44d88612fea8a8f36de82e1278abb02f");
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.size, Some(68));
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_fp_with_wildcard_size_and_flevel() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:*:Eicar-Test-Signature:73";
        let parsed = FpSignature::parse(sig).unwrap();

        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.size, None);
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_fp_rejects_non_md5_hash() {
        let sig = "0059ee2322c3301263c8006fd780d7fe95a30572:1705472:Example";
        assert!(FpSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_fp_rejects_section_hash_format() {
        let sig = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature";
        assert!(FpSignature::parse(sig).is_err());
    }
}
