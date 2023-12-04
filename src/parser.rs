use anyhow::{Context, Result};
use std::fmt::Display;

#[derive(Debug)]
pub struct HashSignature<'p> {
    pub name: &'p str,
    pub hash: &'p str,
    pub filesize: u64,
}

impl<'p> HashSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<HashSignature<'p>> {
        let name = sig.split(':').last().with_context(|| "Can't find name")?;
        let hash = sig.split(':').nth(0).with_context(|| "Can't find hash")?;
        let filesize = sig.split(':').nth(1).with_context(|| "Can't find filesize")?.parse::<u64>()?;
        Ok(HashSignature {
            name,
            hash,
            filesize,
        })
    }
}

impl<'p> Display for HashSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "import \"hash\"
rule {}
{{
    meta:
        original_ident = \"{}\"
    condition:
        hash.md5(0, {}) == \"{}\"
}}",
            self.name.replace(".", "_"),
            self.name,
            self.filesize,
            self.hash
        )
    }
}
