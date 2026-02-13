use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct WdbSignature<'p> {
    pub raw: &'p str,
    pub record_type: char,
    pub filter_flags: Option<&'p str>,
    pub pattern: &'p str,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

impl<'p> WdbSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let (record, payload) = sig.split_once(':').ok_or_else(|| {
            anyhow!("Invalid wdb signature: malformed record (missing ':' delimiter)")
        })?;

        if record.is_empty() {
            return Err(anyhow!(
                "Invalid wdb signature: malformed record (missing record type prefix)"
            ));
        }

        let record_type = record.chars().next().unwrap();
        if !matches!(record_type, 'X' | 'Y' | 'M') {
            return Err(anyhow!(
                "Invalid wdb signature: unsupported record type '{record_type}' (expected 'X', 'Y', or 'M')"
            ));
        }

        if record.len() != 1 {
            return Err(anyhow!(
                "Invalid wdb signature: malformed record type segment (expected exactly 'X', 'Y', or 'M' before ':')"
            ));
        }

        let filter_flags = None;

        let (pattern, min_flevel, max_flevel) = split_pattern_and_flevel(payload);
        if pattern.is_empty() {
            return Err(anyhow!(
                "Invalid wdb signature: malformed record (empty pattern payload)"
            ));
        }

        Ok(Self {
            raw: sig,
            record_type,
            filter_flags,
            pattern,
            min_flevel,
            max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::WdbSignature {
        ir::WdbSignature {
            raw: self.raw.to_string(),
            record_type: self.record_type.to_string(),
            filter_flags: self.filter_flags.map(|v| v.to_string()),
            pattern: self.pattern.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for WdbSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_wdb_signature(&self.to_ir()))
    }
}

fn split_pattern_and_flevel(payload: &str) -> (&str, Option<u32>, Option<u32>) {
    // ClamAV reference: libclamav/regex_list.c:functionality_level_check
    // - only parses trailing functionality level in `:min-max` form
    // - if the trailing token is not numeric `min-max`, it is treated as part of the pattern
    let Some((pattern, suffix)) = payload.rsplit_once(':') else {
        return (payload, None, None);
    };

    let Some((min_str, max_str)) = suffix.split_once('-') else {
        return (payload, None, None);
    };

    if min_str.is_empty() || !is_ascii_digits(min_str) {
        return (payload, None, None);
    }
    if !max_str.is_empty() && !is_ascii_digits(max_str) {
        return (payload, None, None);
    }

    let Ok(min_flevel) = min_str.parse::<u32>() else {
        return (payload, None, None);
    };
    let max_flevel = if max_str.is_empty() {
        None
    } else {
        let Ok(v) = max_str.parse::<u32>() else {
            return (payload, None, None);
        };
        Some(v)
    };

    (pattern, Some(min_flevel), max_flevel)
}

fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_m_wdb() {
        let sig = "M:www\\.google\\.ro:www\\.google\\.com";
        let parsed = WdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.record_type, 'M');
        assert_eq!(parsed.filter_flags, None);
        assert_eq!(parsed.pattern, "www\\.google\\.ro:www\\.google\\.com");
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_x_wdb_with_flevel_range() {
        let sig = "X:.+\\.amazon\\.(at|ca)([/?].*)?:.+\\.amazon\\.com([/?].*)?:20-30";
        let parsed = WdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.record_type, 'X');
        assert_eq!(
            parsed.pattern,
            ".+\\.amazon\\.(at|ca)([/?].*)?:.+\\.amazon\\.com([/?].*)?"
        );
        assert_eq!(parsed.min_flevel, Some(20));
        assert_eq!(parsed.max_flevel, Some(30));
    }

    #[test]
    fn parse_y_wdb_with_open_ended_flevel() {
        let sig = "Y:https?://safe\\.example\\.com([/?].*)?:17-";
        let parsed = WdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.record_type, 'Y');
        assert_eq!(parsed.pattern, "https?://safe\\.example\\.com([/?].*)?");
        assert_eq!(parsed.min_flevel, Some(17));
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_wdb_does_not_extract_non_numeric_suffix_as_flevel() {
        let sig = "M:www\\.google\\.ro:www\\.google\\.com:foo-bar";
        let parsed = WdbSignature::parse(sig).unwrap();

        assert_eq!(
            parsed.pattern,
            "www\\.google\\.ro:www\\.google\\.com:foo-bar"
        );
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_wdb_rejects_missing_delimiter() {
        assert!(WdbSignature::parse("Mwww\\.google\\.rowww\\.google\\.com").is_err());
    }

    #[test]
    fn parse_wdb_rejects_unsupported_record_type() {
        assert!(WdbSignature::parse("H:www\\.google\\.ro:www\\.google\\.com").is_err());
    }

    #[test]
    fn parse_wdb_rejects_empty_pattern() {
        assert!(WdbSignature::parse("X:").is_err());
    }
}
