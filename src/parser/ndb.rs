use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct NdbSignature<'p> {
    pub name: &'p str,
    pub target_type: &'p str,
    pub offset: &'p str,
    pub body: &'p str,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

impl<'p> NdbSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let parts: Vec<&str> = sig.split(':').collect();
        if parts.len() < 4 {
            return Err(anyhow!("Invalid ndb signature: not enough parts"));
        }

        let mut suffix_count = 0usize;
        let mut min_flevel = None;
        let mut max_flevel = None;

        if parts.len() >= 5 {
            if let Some(last) = parts.last() {
                if is_numeric(last) {
                    suffix_count = 1;
                }
            }

            if parts.len() >= 6 && suffix_count == 1 && is_numeric(parts[parts.len() - 2]) {
                suffix_count = 2;
            }
        }

        match suffix_count {
            1 => {
                min_flevel = Some(parts[parts.len() - 1].parse::<u32>()?);
            }
            2 => {
                min_flevel = Some(parts[parts.len() - 2].parse::<u32>()?);
                max_flevel = Some(parts[parts.len() - 1].parse::<u32>()?);
            }
            _ => {}
        }

        let body_end = parts.len() - suffix_count;
        if body_end <= 3 {
            return Err(anyhow!("Invalid ndb signature: missing body"));
        }

        let body = &sig[field_start(sig, 3)?..field_end(sig, body_end - 1)?];

        Ok(Self {
            name: parts[0],
            target_type: parts[1],
            offset: parts[2],
            body,
            min_flevel,
            max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::NdbSignature {
        ir::NdbSignature {
            name: self.name.to_string(),
            target_type: self.target_type.to_string(),
            offset: self.offset.to_string(),
            body: self.body.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for NdbSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_ndb_signature(&self.to_ir()))
    }
}

fn is_numeric(input: &str) -> bool {
    !input.is_empty() && input.chars().all(|c| c.is_ascii_digit())
}

fn field_start(input: &str, field_index: usize) -> Result<usize> {
    if field_index == 0 {
        return Ok(0);
    }

    let mut found = 0usize;
    for (i, ch) in input.char_indices() {
        if ch == ':' {
            found += 1;
            if found == field_index {
                return Ok(i + 1);
            }
        }
    }

    Err(anyhow!("Invalid ndb signature: missing field start"))
}

fn field_end(input: &str, field_index: usize) -> Result<usize> {
    let mut current_field = 0usize;
    for (i, ch) in input.char_indices() {
        if ch == ':' {
            if current_field == field_index {
                return Ok(i);
            }
            current_field += 1;
        }
    }

    if current_field == field_index {
        return Ok(input.len());
    }

    Err(anyhow!("Invalid ndb signature: missing field end"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_ndb() {
        let sig = "Win.Trojan.Example-1:0:*:41424344";
        let parsed = NdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.name, "Win.Trojan.Example-1");
        assert_eq!(parsed.target_type, "0");
        assert_eq!(parsed.offset, "*");
        assert_eq!(parsed.body, "41424344");
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_ndb_with_single_flevel() {
        let sig = "Win.Trojan.Example-1:0:*:41424344:73";
        let parsed = NdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.body, "41424344");
        assert_eq!(parsed.min_flevel, Some(73));
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_ndb_with_min_and_max_flevel() {
        let sig = "Win.Trojan.Example-1:0:*:41424344:73:255";
        let parsed = NdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.body, "41424344");
        assert_eq!(parsed.min_flevel, Some(73));
        assert_eq!(parsed.max_flevel, Some(255));
    }

    #[test]
    fn parse_ndb_with_colon_inside_body() {
        let sig = "Win.Trojan.Example-1:0:*:AA:BB:73";
        let parsed = NdbSignature::parse(sig).unwrap();

        assert_eq!(parsed.body, "AA:BB");
        assert_eq!(parsed.min_flevel, Some(73));
        assert_eq!(parsed.max_flevel, None);
    }
}
