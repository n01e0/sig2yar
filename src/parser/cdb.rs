use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct CdbSignature<'p> {
    pub name: &'p str,
    pub container_type: &'p str,
    pub container_size: &'p str,
    pub filename_regexp: &'p str,
    pub file_size_in_container: &'p str,
    pub file_size_real: &'p str,
    pub is_encrypted: &'p str,
    pub file_pos: &'p str,
    pub res1: &'p str,
    pub res2: &'p str,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

impl<'p> CdbSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let parts: Vec<&str> = sig.split(':').collect();
        if !(10..=12).contains(&parts.len()) {
            return Err(anyhow!(
                "Invalid cdb signature: malformed record (expected 10..12 fields)"
            ));
        }

        if !is_valid_container_type(parts[1]) {
            return Err(anyhow!(
                "Invalid cdb signature: malformed container type (expected '*' or CL_TYPE_*)"
            ));
        }

        validate_range_or_wildcard(parts[2], "ContainerSize")?;
        validate_range_or_wildcard(parts[4], "FileSizeInContainer")?;
        validate_range_or_wildcard(parts[5], "FileSizeReal")?;
        validate_range_or_wildcard(parts[7], "FilePos")?;

        if !matches!(parts[6], "*" | "0" | "1") {
            return Err(anyhow!(
                "Invalid cdb signature: malformed IsEncrypted field (expected '*', '0', or '1')"
            ));
        }

        let min_flevel = if parts.len() >= 11 {
            Some(parts[10].parse::<u32>().map_err(|_| {
                anyhow!("Invalid cdb signature: malformed MinFL field (expected numeric)")
            })?)
        } else {
            None
        };

        let max_flevel = if parts.len() == 12 {
            Some(parts[11].parse::<u32>().map_err(|_| {
                anyhow!("Invalid cdb signature: malformed MaxFL field (expected numeric)")
            })?)
        } else {
            None
        };

        Ok(Self {
            name: parts[0],
            container_type: parts[1],
            container_size: parts[2],
            filename_regexp: parts[3],
            file_size_in_container: parts[4],
            file_size_real: parts[5],
            is_encrypted: parts[6],
            file_pos: parts[7],
            res1: parts[8],
            res2: parts[9],
            min_flevel,
            max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::CdbSignature {
        ir::CdbSignature {
            name: self.name.to_string(),
            container_type: self.container_type.to_string(),
            container_size: self.container_size.to_string(),
            filename_regexp: self.filename_regexp.to_string(),
            file_size_in_container: self.file_size_in_container.to_string(),
            file_size_real: self.file_size_real.to_string(),
            is_encrypted: self.is_encrypted.to_string(),
            file_pos: self.file_pos.to_string(),
            res1: self.res1.to_string(),
            res2: self.res2.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for CdbSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_cdb_signature(&self.to_ir()))
    }
}

fn is_valid_container_type(value: &str) -> bool {
    value == "*" || (value.starts_with("CL_TYPE_") && value.len() > "CL_TYPE_".len())
}

fn validate_range_or_wildcard(value: &str, field_name: &str) -> Result<()> {
    if value == "*" {
        return Ok(());
    }

    if let Some((start, end)) = value.split_once('-') {
        if !is_numeric(start) || !is_numeric(end) {
            return Err(anyhow!(
                "Invalid cdb signature: malformed {field_name} field (expected number or x-y range)"
            ));
        }

        start.parse::<u32>().map_err(|_| {
            anyhow!("Invalid cdb signature: malformed {field_name} field (range start out of u32)")
        })?;
        end.parse::<u32>().map_err(|_| {
            anyhow!("Invalid cdb signature: malformed {field_name} field (range end out of u32)")
        })?;
        return Ok(());
    }

    if !is_numeric(value) {
        return Err(anyhow!(
            "Invalid cdb signature: malformed {field_name} field (expected number or x-y range)"
        ));
    }

    value.parse::<u32>().map_err(|_| {
        anyhow!("Invalid cdb signature: malformed {field_name} field (value out of u32)")
    })?;

    Ok(())
}

fn is_numeric(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_cdb() {
        let sig = "Container.Test-1:CL_TYPE_ZIP:*:.*\\.exe:10-20:20-40:0:1:*:*";
        let parsed = CdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "Container.Test-1");
        assert_eq!(parsed.container_type, "CL_TYPE_ZIP");
        assert_eq!(parsed.container_size, "*");
        assert_eq!(parsed.filename_regexp, ".*\\.exe");
        assert_eq!(parsed.file_size_in_container, "10-20");
        assert_eq!(parsed.file_size_real, "20-40");
        assert_eq!(parsed.is_encrypted, "0");
        assert_eq!(parsed.file_pos, "1");
        assert_eq!(parsed.res1, "*");
        assert_eq!(parsed.res2, "*");
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_cdb_with_flevels() {
        let sig = "Container.Test-2:*:1-2:.*:3:4:1:5:*:*:120:255";
        let parsed = CdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.min_flevel, Some(120));
        assert_eq!(parsed.max_flevel, Some(255));
    }

    #[test]
    fn parse_cdb_rejects_wrong_token_count() {
        let sig = "Container.Test-3:CL_TYPE_ZIP:*:.*:1:1:0:1:*";
        assert!(CdbSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_cdb_rejects_invalid_container_type() {
        let sig = "Container.Test-4:ZIP:*:.*:1:1:0:1:*:*";
        assert!(CdbSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_cdb_rejects_invalid_range_field() {
        let sig = "Container.Test-5:CL_TYPE_ZIP:1-:.*:1:1:0:1:*:*";
        assert!(CdbSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_cdb_rejects_invalid_encryption_flag() {
        let sig = "Container.Test-6:CL_TYPE_ZIP:*:.*:1:1:2:1:*:*";
        assert!(CdbSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_cdb_rejects_non_numeric_min_flevel() {
        let sig = "Container.Test-7:CL_TYPE_ZIP:*:.*:1:1:0:1:*:*:xx";
        assert!(CdbSignature::parse(sig).is_err());
    }
}
