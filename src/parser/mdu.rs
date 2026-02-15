use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

use super::hash::{HashSignature, HashSource, HashType};

#[derive(Debug)]
pub struct MduSignature<'p> {
    pub name: &'p str,
    pub hash: &'p str,
    pub hash_type: HashType,
    pub size: Option<u64>,
    pub min_flevel: Option<u32>,
}

impl<'p> MduSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
        // - docs: manual/Signatures/HashSignatures (`PESectionSize:Hash:MalwareName[:MinFL]`)
        let parsed = HashSignature::parse(sig)?;

        if parsed.hash_type != HashType::Md5 {
            return Err(anyhow!(
                "Invalid mdu signature: expected MD5 hash (32 hex chars)"
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
            HashSource::Section { size } => size,
            HashSource::File { .. } => {
                return Err(anyhow!(
                    "Invalid mdu signature: expected section-hash format (file hash is not valid for .mdu)"
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

    pub fn to_ir(&self) -> ir::MduSignature {
        ir::MduSignature {
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

impl<'p> Display for MduSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_mdu_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_mdu_signature() {
        let sig = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature";
        let parsed = MduSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "Eicar-Test-Signature");
        assert_eq!(parsed.hash, "3ea7d00dedd30bcdf46191358c36ffa4");
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.size, Some(45056));
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_mdu_with_wildcard_size_and_flevel() {
        let sig = "*:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature:73";
        let parsed = MduSignature::parse(sig).unwrap();

        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.size, None);
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_mdu_rejects_non_md5_hash() {
        let sig = "45056:0059ee2322c3301263c8006fd780d7fe95a30572:Example";
        assert!(MduSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_mdu_rejects_file_hash_format() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
        assert!(MduSignature::parse(sig).is_err());
    }
}
