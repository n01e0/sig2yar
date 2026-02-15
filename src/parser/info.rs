use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct InfoSignature<'p> {
    pub raw: &'p str,
    pub record_type: &'p str,
    pub payload: &'p str,
}

impl<'p> InfoSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures (`*.info` contains DB metadata/index info)
        // - observed records: `ClamAV-VDB:...`, `<file>:<size>:<sha256>`, `DSIG:...`
        let raw = sig.trim_end_matches(['\r', '\n']);
        if raw.trim().is_empty() {
            return Err(anyhow!("Invalid info record: empty line"));
        }

        let (record_type, payload) = raw
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid info record: missing ':' delimiter"))?;

        if record_type.is_empty() {
            return Err(anyhow!("Invalid info record: empty record type"));
        }
        if payload.is_empty() {
            return Err(anyhow!("Invalid info record: empty payload"));
        }

        Ok(Self {
            raw,
            record_type,
            payload,
        })
    }

    pub fn to_ir(&self) -> ir::InfoSignature {
        ir::InfoSignature {
            raw: self.raw.to_string(),
            record_type: self.record_type.to_string(),
            payload: self.payload.to_string(),
        }
    }
}

impl<'p> Display for InfoSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_info_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clamav_vdb_info_record() {
        let sig = "ClamAV-VDB:14 Feb 2026 07-25 +0000:27912:355104:90:X:X:svc.clamav-publisher:1771053920";
        let parsed = InfoSignature::parse(sig).unwrap();

        assert_eq!(parsed.raw, sig);
        assert_eq!(parsed.record_type, "ClamAV-VDB");
        assert_eq!(
            parsed.payload,
            "14 Feb 2026 07-25 +0000:27912:355104:90:X:X:svc.clamav-publisher:1771053920"
        );
    }

    #[test]
    fn parse_dsig_info_record() {
        let sig = "DSIG:abcDEF012+/=";
        let parsed = InfoSignature::parse(sig).unwrap();

        assert_eq!(parsed.record_type, "DSIG");
        assert_eq!(parsed.payload, "abcDEF012+/=");
    }

    #[test]
    fn parse_info_rejects_missing_delimiter() {
        assert!(InfoSignature::parse("ClamAV-VDB").is_err());
    }

    #[test]
    fn parse_info_rejects_empty_payload() {
        assert!(InfoSignature::parse("DSIG:").is_err());
    }
}
