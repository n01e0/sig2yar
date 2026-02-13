use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct IdbSignature<'p> {
    pub name: &'p str,
    pub group1: &'p str,
    pub group2: &'p str,
    pub icon_hash: &'p str,
}

impl<'p> IdbSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let parts: Vec<&str> = sig.split(':').collect();
        if parts.len() != 4 {
            return Err(anyhow!(
                "Invalid idb signature: malformed record (expected 4 fields)"
            ));
        }

        let icon_hash = parts[3];
        if icon_hash.len() != 124 {
            return Err(anyhow!(
                "Invalid idb signature: malformed icon hash (expected 124 hex chars)"
            ));
        }
        if !icon_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "Invalid idb signature: malformed icon hash (non-hex character found)"
            ));
        }

        let icon_size = u8::from_str_radix(&icon_hash[..2], 16)?;
        if !matches!(icon_size, 16 | 24 | 32) {
            return Err(anyhow!(
                "Invalid idb signature: malformed icon hash (unsupported icon size prefix {icon_size})"
            ));
        }

        Ok(Self {
            name: parts[0],
            group1: parts[1],
            group2: parts[2],
            icon_hash,
        })
    }

    pub fn to_ir(&self) -> ir::IdbSignature {
        ir::IdbSignature {
            name: self.name.to_string(),
            group1: self.group1.to_string(),
            group2: self.group2.to_string(),
            icon_hash: self.icon_hash.to_string(),
        }
    }
}

impl<'p> Display for IdbSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_idb_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_icon_hash() -> String {
        format!("10{}", "0".repeat(122))
    }

    #[test]
    fn parse_basic_idb() {
        let sig = format!("Icon.Test:GROUP_A:GROUP_B:{}", valid_icon_hash());
        let parsed = IdbSignature::parse(sig.as_str()).unwrap();

        assert_eq!(parsed.name, "Icon.Test");
        assert_eq!(parsed.group1, "GROUP_A");
        assert_eq!(parsed.group2, "GROUP_B");
        assert_eq!(parsed.icon_hash.len(), 124);
    }

    #[test]
    fn parse_idb_rejects_wrong_token_count() {
        let sig = format!("Icon.Test:GROUP_A:{}", valid_icon_hash());
        assert!(IdbSignature::parse(sig.as_str()).is_err());
    }

    #[test]
    fn parse_idb_rejects_non_hex_hash() {
        let sig = format!("Icon.Test:GROUP_A:GROUP_B:10{}", "g".repeat(122));
        assert!(IdbSignature::parse(sig.as_str()).is_err());
    }

    #[test]
    fn parse_idb_rejects_wrong_hash_length() {
        let sig = "Icon.Test:GROUP_A:GROUP_B:10";
        assert!(IdbSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_idb_rejects_unsupported_size_prefix() {
        let sig = format!("Icon.Test:GROUP_A:GROUP_B:11{}", "0".repeat(122));
        assert!(IdbSignature::parse(sig.as_str()).is_err());
    }
}
