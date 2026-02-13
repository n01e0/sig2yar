use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct CrbSignature<'p> {
    pub name: &'p str,
    pub trusted: &'p str,
    pub subject: &'p str,
    pub serial: &'p str,
    pub pubkey: &'p str,
    pub exponent: &'p str,
    pub code_sign: &'p str,
    pub time_sign: &'p str,
    pub cert_sign: &'p str,
    pub not_before: &'p str,
    pub comment: &'p str,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

impl<'p> CrbSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let parts: Vec<&str> = sig.split(';').collect();
        if !(11..=13).contains(&parts.len()) {
            return Err(anyhow!(
                "Invalid crb signature: malformed record (expected 11..13 fields)"
            ));
        }

        validate_binary_flag(parts[1], "Trusted")?;
        validate_sha1(parts[2], "Subject")?;
        if !parts[3].is_empty() {
            validate_sha1(parts[3], "Serial")?;
        }

        if parts[4].is_empty() || !parts[4].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "Invalid crb signature: malformed Pubkey field (expected non-empty hex)"
            ));
        }

        validate_binary_flag(parts[6], "CodeSign")?;
        validate_binary_flag(parts[7], "TimeSign")?;
        validate_binary_flag(parts[8], "CertSign")?;

        if !parts[9].is_empty() && !is_numeric(parts[9]) {
            return Err(anyhow!(
                "Invalid crb signature: malformed NotBefore field (expected numeric or empty)"
            ));
        }

        let min_flevel = if parts.len() >= 12 {
            Some(parts[11].parse::<u32>().map_err(|_| {
                anyhow!("Invalid crb signature: malformed MinFL field (expected numeric)")
            })?)
        } else {
            None
        };

        let max_flevel = if parts.len() == 13 {
            Some(parts[12].parse::<u32>().map_err(|_| {
                anyhow!("Invalid crb signature: malformed MaxFL field (expected numeric)")
            })?)
        } else {
            None
        };

        Ok(Self {
            name: parts[0],
            trusted: parts[1],
            subject: parts[2],
            serial: parts[3],
            pubkey: parts[4],
            exponent: parts[5],
            code_sign: parts[6],
            time_sign: parts[7],
            cert_sign: parts[8],
            not_before: parts[9],
            comment: parts[10],
            min_flevel,
            max_flevel,
        })
    }

    pub fn to_ir(&self) -> ir::CrbSignature {
        ir::CrbSignature {
            name: self.name.to_string(),
            trusted: self.trusted.to_string(),
            subject: self.subject.to_string(),
            serial: self.serial.to_string(),
            pubkey: self.pubkey.to_string(),
            exponent: self.exponent.to_string(),
            code_sign: self.code_sign.to_string(),
            time_sign: self.time_sign.to_string(),
            cert_sign: self.cert_sign.to_string(),
            not_before: self.not_before.to_string(),
            comment: self.comment.to_string(),
            min_flevel: self.min_flevel,
            max_flevel: self.max_flevel,
        }
    }
}

impl<'p> Display for CrbSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_crb_signature(&self.to_ir()))
    }
}

fn validate_binary_flag(value: &str, field_name: &str) -> Result<()> {
    if matches!(value, "0" | "1") {
        Ok(())
    } else {
        Err(anyhow!(
            "Invalid crb signature: malformed {field_name} field (expected '0' or '1')"
        ))
    }
}

fn validate_sha1(value: &str, field_name: &str) -> Result<()> {
    if value.len() != 40 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Invalid crb signature: malformed {field_name} field (expected 40-char SHA1 hex)"
        ));
    }
    Ok(())
}

fn is_numeric(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha1_hex(ch: char) -> String {
        std::iter::repeat_n(ch, 40).collect()
    }

    #[test]
    fn parse_basic_crb() {
        let subject = sha1_hex('a');
        let serial = sha1_hex('b');
        let sig =
            format!("Trusted.Cert-1;1;{subject};{serial};A1B2C3D4;010001;1;0;1;0;baseline-comment");

        let parsed = CrbSignature::parse(sig.as_str()).unwrap();
        assert_eq!(parsed.name, "Trusted.Cert-1");
        assert_eq!(parsed.trusted, "1");
        assert_eq!(parsed.subject, subject);
        assert_eq!(parsed.serial, serial);
        assert_eq!(parsed.pubkey, "A1B2C3D4");
        assert_eq!(parsed.exponent, "010001");
        assert_eq!(parsed.code_sign, "1");
        assert_eq!(parsed.time_sign, "0");
        assert_eq!(parsed.cert_sign, "1");
        assert_eq!(parsed.not_before, "0");
        assert_eq!(parsed.comment, "baseline-comment");
        assert_eq!(parsed.min_flevel, None);
        assert_eq!(parsed.max_flevel, None);
    }

    #[test]
    fn parse_crb_allows_empty_serial_and_not_before() {
        let subject = sha1_hex('a');
        let sig = format!(
            "Trusted.Cert-2;0;{subject};;ABCDEF;ignored-exp;0;1;0;;comment-with-empty-serial"
        );

        let parsed = CrbSignature::parse(sig.as_str()).unwrap();
        assert_eq!(parsed.serial, "");
        assert_eq!(parsed.not_before, "");
    }

    #[test]
    fn parse_crb_with_flevels() {
        let subject = sha1_hex('c');
        let serial = sha1_hex('d');
        let sig = format!(
            "Trusted.Cert-3;1;{subject};{serial};ABCDEF;010001;1;1;1;1700000000;comment;120;255"
        );

        let parsed = CrbSignature::parse(sig.as_str()).unwrap();
        assert_eq!(parsed.min_flevel, Some(120));
        assert_eq!(parsed.max_flevel, Some(255));
    }

    #[test]
    fn parse_crb_rejects_wrong_token_count() {
        let subject = sha1_hex('a');
        let sig = format!("Trusted.Cert-4;1;{subject};;ABCDEF;010001;1;0;1;0");
        assert!(CrbSignature::parse(sig.as_str()).is_err());
    }

    #[test]
    fn parse_crb_rejects_invalid_subject() {
        let sig = "Trusted.Cert-5;1;abcd;;ABCDEF;010001;1;0;1;0;comment";
        assert!(CrbSignature::parse(sig).is_err());
    }

    #[test]
    fn parse_crb_rejects_invalid_serial_when_present() {
        let subject = sha1_hex('a');
        let sig = format!("Trusted.Cert-6;1;{subject};xyz;ABCDEF;010001;1;0;1;0;comment");
        assert!(CrbSignature::parse(sig.as_str()).is_err());
    }

    #[test]
    fn parse_crb_rejects_invalid_bit_flags() {
        let subject = sha1_hex('a');
        let serial = sha1_hex('b');
        let sig = format!("Trusted.Cert-7;2;{subject};{serial};ABCDEF;010001;1;0;1;0;comment");
        assert!(CrbSignature::parse(sig.as_str()).is_err());
    }

    #[test]
    fn parse_crb_rejects_invalid_not_before() {
        let subject = sha1_hex('a');
        let serial = sha1_hex('b');
        let sig = format!("Trusted.Cert-8;1;{subject};{serial};ABCDEF;010001;1;0;1;soon;comment");
        assert!(CrbSignature::parse(sig.as_str()).is_err());
    }
}
