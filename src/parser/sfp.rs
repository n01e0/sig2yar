use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

use super::hash::{HashSignature, HashSource, HashType};

#[derive(Debug)]
pub struct SfpSignature<'p> {
    pub name: &'p str,
    pub hash: &'p str,
    pub hash_type: HashType,
    pub size: Option<u64>,
    pub min_flevel: Option<u32>,
}

impl<'p> SfpSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures/AllowLists (`.sfp` uses SHA1/SHA256 file hash signature format)
        // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
        let parsed = HashSignature::parse(sig)?;

        if !matches!(parsed.hash_type, HashType::Sha1 | HashType::Sha256) {
            return Err(anyhow!(
                "Invalid sfp signature: expected SHA1/SHA256 hash (40/64 hex chars)"
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
                    "Invalid sfp signature: expected file-hash format (section hash is not valid for .sfp)"
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

    pub fn to_ir(&self) -> ir::SfpSignature {
        ir::SfpSignature {
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

impl<'p> Display for SfpSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_sfp_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_sha1_sfp_signature() {
        let sig = "0059ee2322c3301263c8006fd780d7fe95a30572:1705472:Example";
        let parsed = SfpSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "Example");
        assert_eq!(parsed.hash, "0059ee2322c3301263c8006fd780d7fe95a30572");
        assert_eq!(parsed.hash_type, HashType::Sha1);
        assert_eq!(parsed.size, Some(1705472));
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_basic_sha256_sfp_signature() {
        let sig = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature";
        let parsed = SfpSignature::parse(sig).unwrap();

        assert_eq!(parsed.hash_type, HashType::Sha256);
        assert_eq!(parsed.size, Some(68));
    }

    #[test]
    fn parse_sfp_with_wildcard_size_and_flevel() {
        let sig = "f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:*:Eicar-Test-Signature:73";
        let parsed = SfpSignature::parse(sig).unwrap();

        assert_eq!(parsed.hash_type, HashType::Sha256);
        assert_eq!(parsed.size, None);
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_sfp_rejects_md5_hash() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
        assert!(SfpSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_sfp_rejects_section_hash_format() {
        let sig = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature";
        assert!(SfpSignature::parse(sig).is_err());
    }
}
