use anyhow::{anyhow, Context, Result};
use std::fmt::Display;

#[derive(Debug)]
pub struct HashSignature<'p> {
    pub name: &'p str,
    pub hash: &'p str,
    pub hash_type: HashType,
    pub source: HashSource,
    pub min_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashSource {
    File { size: Option<u64> },
    Section { size: Option<u64> },
}

impl<'p> HashSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<HashSignature<'p>> {
        let parts: Vec<&str> = sig.split(':').collect();
        if parts.len() < 3 {
            return Err(anyhow!("Invalid hash signature: not enough parts"));
        }

        let (min_flevel, name_idx) = match parts.last() {
            Some(last) if last.chars().all(|c| c.is_ascii_digit()) => {
                let flevel = last.parse::<u32>()?;
                if parts.len() < 4 {
                    return Err(anyhow!("Invalid hash signature: missing name"));
                }
                (Some(flevel), parts.len() - 2)
            }
            _ => (None, parts.len() - 1),
        };

        let name = parts[name_idx];
        let first = parts[0];
        let second = parts[1];

        if let Some(hash_type) = parse_hash_type(first) {
            let size = parse_optional_size(second)?;
            ensure_size_allowed(size, min_flevel)?;
            return Ok(HashSignature {
                name,
                hash: first,
                hash_type,
                source: HashSource::File { size },
                min_flevel,
            });
        }

        if first.chars().all(|c| c.is_ascii_digit()) {
            if let Some(hash_type) = parse_hash_type(second) {
                let section_size = Some(first.parse::<u64>()?);
                return Ok(HashSignature {
                    name,
                    hash: second,
                    hash_type,
                    source: HashSource::Section { size: section_size },
                    min_flevel,
                });
            }
        }

        if first == "*" {
            if let Some(hash_type) = parse_hash_type(second) {
                let section_size = parse_optional_size(first)?;
                ensure_size_allowed(section_size, min_flevel)?;
                return Ok(HashSignature {
                    name,
                    hash: second,
                    hash_type,
                    source: HashSource::Section { size: section_size },
                    min_flevel,
                });
            }
        }

        Err(anyhow!("Invalid hash signature format"))
    }
}

impl<'p> Display for HashSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rule_name = self.name.replace('.', "_").replace('-', "_");
        let mut meta = format!("        original_ident = \"{}\"\n", self.name);
        if let Some(flevel) = self.min_flevel {
            meta.push_str(&format!("        min_flevel = \"{flevel}\"\n"));
        }

        match self.source {
            HashSource::File { size } => {
                let size_expr = match size {
                    Some(size) => size.to_string(),
                    None => "filesize".to_string(),
                };
                write!(
                    f,
                    "import \"hash\"
rule {}
{{
    meta:
{}
    condition:
        hash.{}(0, {}) == \"{}\"
}}",
                    rule_name,
                    meta,
                    self.hash_type.yara_fn(),
                    size_expr,
                    self.hash
                )
            }
            HashSource::Section { size } => {
                let section_size = match size {
                    Some(size) => size.to_string(),
                    None => "*".to_string(),
                };
                meta.push_str(&format!(
                    "        clamav_section_size = \"{section_size}\"\n"
                ));
                meta.push_str(&format!(
                    "        clamav_hash_type = \"{}\"\n",
                    self.hash_type.yara_fn()
                ));
                meta.push_str("        clamav_unsupported = \"section_hash\"\n");
                write!(
                    f,
                    "rule {}
{{
    meta:
{}
    condition:
        false
}}",
                    rule_name, meta
                )
            }
        }
    }
}

impl HashType {
    fn yara_fn(&self) -> &'static str {
        match self {
            HashType::Md5 => "md5",
            HashType::Sha1 => "sha1",
            HashType::Sha256 => "sha256",
        }
    }
}

fn parse_hash_type(input: &str) -> Option<HashType> {
    let hash_type = match input.len() {
        32 => HashType::Md5,
        40 => HashType::Sha1,
        64 => HashType::Sha256,
        _ => return None,
    };

    if input.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash_type)
    } else {
        None
    }
}

fn parse_optional_size(input: &str) -> Result<Option<u64>> {
    if input == "*" {
        return Ok(None);
    }
    Ok(Some(
        input
            .parse::<u64>()
            .with_context(|| "Can't parse size")?,
    ))
}

fn ensure_size_allowed(size: Option<u64>, min_flevel: Option<u32>) -> Result<()> {
    if size.is_some() {
        return Ok(());
    }

    match min_flevel {
        Some(level) if level >= 73 => Ok(()),
        _ => Err(anyhow!(
            "Wildcard size requires min f-level (>=73) to be specified"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_md5_hdb() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.name, "Eicar-Test-Signature");
        assert_eq!(parsed.hash, "44d88612fea8a8f36de82e1278abb02f");
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.source, HashSource::File { size: Some(68) });
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_md5_hsb_with_flevel() {
        let sig = "4b3858c8b35e964a5eb0e291ff69ced6:78454:Xls.Exploit.Agent-4323916-1:73";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.source, HashSource::File { size: Some(78454) });
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_sha1_hsb_with_flevel() {
        let sig = "0059ee2322c3301263c8006fd780d7fe95a30572:1705472:Win.Keylogger.Generic-7604980-0:73";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Sha1);
        assert_eq!(parsed.source, HashSource::File { size: Some(1705472) });
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_sha256_hsb_no_flevel() {
        let sig = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Sha256);
        assert_eq!(parsed.source, HashSource::File { size: Some(68) });
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_size_unknown() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:*:Eicar-Test-Signature";
        assert!(HashSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_size_unknown_with_flevel() {
        let sig = "44d88612fea8a8f36de82e1278abb02f:*:Eicar-Test-Signature:73";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.source, HashSource::File { size: None });
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_section_hash_mdb() {
        let sig = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(
            parsed.source,
            HashSource::Section {
                size: Some(45056)
            }
        );
        assert_eq!(parsed.min_flevel, None);
    }

    #[test]
    fn parse_section_hash_with_flevel() {
        let sig = "91648:550a9b573224aa75418c852080b59af3:Win.Packer.Agent-6412293-0:73";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(
            parsed.source,
            HashSource::Section {
                size: Some(91648)
            }
        );
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_section_size_unknown_requires_flevel() {
        let sig = "*:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Eicar-Test-Signature";
        assert!(HashSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_section_size_unknown_with_flevel() {
        let sig = "*:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Eicar-Test-Signature:73";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Sha256);
        assert_eq!(parsed.source, HashSource::Section { size: None });
        assert_eq!(parsed.min_flevel, Some(73));
    }

    #[test]
    fn parse_import_hash_signature() {
        let sig = "4b3858c8b35e964a5eb0e291ff69ced6:78454:Xls.Exploit.Agent-4323916-1";
        let parsed = HashSignature::parse(sig).unwrap();
        assert_eq!(parsed.hash_type, HashType::Md5);
        assert_eq!(parsed.source, HashSource::File { size: Some(78454) });
    }
}
