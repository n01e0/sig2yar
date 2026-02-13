use anyhow::{anyhow, Result};
use std::fmt::Display;

use crate::{ir, yara};

#[derive(Debug)]
pub struct CbcSignature<'p> {
    pub raw: &'p str,
}

impl<'p> CbcSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        // ClamAV reference:
        // - docs: manual/Signatures/BytecodeSignatures (`.cbc` is ASCII-encoded bytecode)
        // - source: libclamav/readdb.c:2332-2387 (`cli_loadcbc` passes payload to `cli_bytecode_load`)
        let raw = sig.trim_end_matches(['\r', '\n']);

        if raw.trim().is_empty() {
            return Err(anyhow!(
                "Invalid cbc signature: malformed payload (empty bytecode content)"
            ));
        }

        if !raw.is_ascii() {
            return Err(anyhow!(
                "Invalid cbc signature: malformed payload (cbc is expected to be ASCII-encoded bytecode)"
            ));
        }

        Ok(Self { raw })
    }

    pub fn to_ir(&self) -> ir::CbcSignature {
        ir::CbcSignature {
            raw: self.raw.to_string(),
        }
    }
}

impl<'p> Display for CbcSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", yara::render_cbc_signature(&self.to_ir()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_cbc_payload() {
        let sig = "VIRUSNAME Bytecode.Sample\nFUNCTIONALITY_LEVEL_MIN 51\n";
        let parsed = CbcSignature::parse(sig).unwrap();

        assert_eq!(
            parsed.raw,
            "VIRUSNAME Bytecode.Sample\nFUNCTIONALITY_LEVEL_MIN 51"
        );
    }

    #[test]
    fn parse_multiline_cbc_payload() {
        let sig = "BYTECODE\n41424344\nEND";
        let parsed = CbcSignature::parse(sig).unwrap();

        assert_eq!(parsed.raw, sig);
    }

    #[test]
    fn parse_cbc_rejects_empty_payload() {
        assert!(CbcSignature::parse(" \n\t ").is_err());
    }

    #[test]
    fn parse_cbc_rejects_non_ascii_payload() {
        assert!(CbcSignature::parse("BYTECODE🙂").is_err());
    }
}
