use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct FtmSignature<'p> {
    pub magic_type: u32,
    pub offset: &'p str,
    pub magic_bytes: &'p str,
    pub name: &'p str,
    pub required_type: &'p str,
    pub detected_type: &'p str,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

impl<'p> FtmSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures/FileTypeMagic
        // - source: libclamav/readdb.c:2468-2600 (`FTM_TOKENS=8`, token count 6..8)
        let parts: Vec<&str> = sig.split(':').collect();
        if !(6..=8).contains(&parts.len()) {
            return Err(anyhow!(
                "Invalid ftm signature: malformed record (expected 6..8 fields)"
            ));
        }

        let magic_type = parts[0].parse::<u32>().map_err(|_| {
            anyhow!("Invalid ftm signature: malformed MagicType field (expected numeric value)")
        })?;

        if parts[1].is_empty() {
            return Err(anyhow!(
                "Invalid ftm signature: malformed Offset field (empty value)"
            ));
        }

        if parts[2].is_empty() {
            return Err(anyhow!(
                "Invalid ftm signature: malformed HexSig field (empty value)"
            ));
        }

        if parts[3].is_empty() {
            return Err(anyhow!(
                "Invalid ftm signature: malformed Name field (empty value)"
            ));
        }

        if !is_valid_cl_type(parts[4]) {
            return Err(anyhow!(
                "Invalid ftm signature: malformed RequiredType field (expected CL_TYPE_*)"
            ));
        }

        if !is_valid_cl_type(parts[5]) {
            return Err(anyhow!(
                "Invalid ftm signature: malformed DetectedType field (expected CL_TYPE_*)"
            ));
        }

        if matches!(magic_type, 0 | 4) {
            if !is_ascii_digits(parts[1]) {
                return Err(anyhow!(
                    "Invalid ftm signature: malformed Offset field (MagicType 0/4 requires numeric offset)"
                ));
            }

            validate_hex_bytes(parts[2])?;
        }

        let min_flevel = if parts.len() >= 7 {
            if parts[6].is_empty() {
                None
            } else {
                Some(parts[6].parse::<u32>().map_err(|_| {
                    anyhow!("Invalid ftm signature: malformed MinFL field (expected numeric)")
                })?)
            }
        } else {
            None
        };

        let max_flevel = if parts.len() == 8 {
            if parts[7].is_empty() {
                None
            } else {
                Some(parts[7].parse::<u32>().map_err(|_| {
                    anyhow!("Invalid ftm signature: malformed MaxFL field (expected numeric)")
                })?)
            }
        } else {
            None
        };

        Ok(Self {
            magic_type,
            offset: parts[1],
            magic_bytes: parts[2],
            name: parts[3],
            required_type: parts[4],
            detected_type: parts[5],
            min_flevel,
            max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::FtmSignature {
        ir::FtmSignature {
            magic_type: self.magic_type,
            offset: self.offset.to_string(),
            magic_bytes: self.magic_bytes.to_string(),
            name: self.name.to_string(),
            required_type: self.required_type.to_string(),
            detected_type: self.detected_type.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for FtmSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_ftm_signature(&self.to_ir()))
    }
}

fn is_valid_cl_type(value: &str) -> bool {
    value.starts_with("CL_TYPE_") && value.len() > "CL_TYPE_".len()
}

fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

fn validate_hex_bytes(value: &str) -> Result<()> {
    if value.len() % 2 != 0 {
        return Err(anyhow!(
            "Invalid ftm signature: malformed HexSig field (hex length must be even for MagicType 0/4)"
        ));
    }

    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Invalid ftm signature: malformed HexSig field (expected hexadecimal bytes for MagicType 0/4)"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_type0_ftm() {
        let sig = "0:0:4D5A:PE32-executable:CL_TYPE_ANY:CL_TYPE_MSEXE";
        let parsed = FtmSignature::parse(sig).unwrap();

        assert_eq!(parsed.magic_type, 0);
        assert_eq!(parsed.offset, "0");
        assert_eq!(parsed.magic_bytes, "4D5A");
        assert_eq!(parsed.name, "PE32-executable");
        assert_eq!(parsed.required_type, "CL_TYPE_ANY");
        assert_eq!(parsed.detected_type, "CL_TYPE_MSEXE");
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_type1_ftm_with_wildcard_offset_and_flevels() {
        let sig = "1:*:25504446:PDF-body:CL_TYPE_ANY:CL_TYPE_PDF:120:255";
        let parsed = FtmSignature::parse(sig).unwrap();

        assert_eq!(parsed.magic_type, 1);
        assert_eq!(parsed.offset, "*");
        assert_eq!(parsed.magic_bytes, "25504446");
        assert_eq!(parsed.min_flevel, Some(120));
        assert_eq!(parsed.max_flevel, Some(255));
    }

    #[test]
    fn parse_type1_ftm_allows_empty_min_flevel_with_max() {
        let sig = "0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121";
        let parsed = FtmSignature::parse(sig).unwrap();

        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, Some(121));
    }

    #[test]
    fn parse_type4_ftm_partition_magic() {
        let sig = "4:1024:482B0004:HFSPlus-partition:CL_TYPE_ANY:CL_TYPE_PART_HFSPLUS";
        let parsed = FtmSignature::parse(sig).unwrap();

        assert_eq!(parsed.magic_type, 4);
        assert_eq!(parsed.offset, "1024");
        assert_eq!(parsed.magic_bytes, "482B0004");
    }

    #[test]
    fn parse_ftm_allows_unknown_magic_type_for_safe_lowering() {
        let sig = "9:0:AA:Vendor-custom:CL_TYPE_ANY:CL_TYPE_TEXT_ASCII";
        let parsed = FtmSignature::parse(sig).unwrap();

        assert_eq!(parsed.magic_type, 9);
        assert_eq!(parsed.offset, "0");
    }

    #[test]
    fn parse_ftm_rejects_wrong_token_count() {
        assert!(FtmSignature::parse("1:*:AA:Name:CL_TYPE_ANY").is_err());
    }

    #[test]
    fn parse_ftm_rejects_non_numeric_magic_type() {
        assert!(FtmSignature::parse("x:0:4D5A:Name:CL_TYPE_ANY:CL_TYPE_MSEXE").is_err());
    }

    #[test]
    fn parse_ftm_rejects_non_cl_type_fields() {
        assert!(FtmSignature::parse("1:*:AA:Name:ANY:CL_TYPE_MSEXE").is_err());
        assert!(FtmSignature::parse("1:*:AA:Name:CL_TYPE_ANY:MSEXE").is_err());
    }

    #[test]
    fn parse_ftm_rejects_type0_type4_non_numeric_offset() {
        assert!(FtmSignature::parse("0:*:4D5A:Name:CL_TYPE_ANY:CL_TYPE_MSEXE").is_err());
        assert!(FtmSignature::parse("4:EP+0:4D5A:Name:CL_TYPE_ANY:CL_TYPE_PART_HFSPLUS").is_err());
    }

    #[test]
    fn parse_ftm_rejects_type0_type4_non_hex_magic_bytes() {
        assert!(FtmSignature::parse("0:0:4D5Z:Name:CL_TYPE_ANY:CL_TYPE_MSEXE").is_err());
        assert!(FtmSignature::parse("4:8:ABC:Name:CL_TYPE_ANY:CL_TYPE_PART_HFSPLUS").is_err());
    }

    #[test]
    fn parse_ftm_rejects_non_numeric_flevel_fields() {
        assert!(FtmSignature::parse("1:*:AA:Name:CL_TYPE_ANY:CL_TYPE_TEXT_ASCII:xx").is_err());
        assert!(FtmSignature::parse("1:*:AA:Name:CL_TYPE_ANY:CL_TYPE_TEXT_ASCII:120:yy").is_err());
    }
}
