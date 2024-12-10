use anyhow::{Result, Context};
use std::fmt::Display;

mod target_description;
use target_description::TargetDescription;

mod expression;
use expression::LogicalExpression;

#[derive(Debug)]
pub struct LogicalSignature<'p> {
    pub name: &'p str,
    pub target_description: TargetDescription<'p>,
    pub logical_expression: LogicalExpression,
    pub subsigs: Vec<&'p str>,
}

impl<'p> LogicalSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let mut parts = sig.split(';').collect::<Vec<&str>>();
        if parts.len() < 4 {
            return Err(anyhow::anyhow!("Invalid signature: not enough parts"));
        }
        let name = parts[0];
        let target_description_block = parts[1];
        let logical_expression = LogicalExpression::parse(String::from(parts[2])).with_context(|| "Can't parse LogicalExpression")?;
        let subsigs = parts.split_off(3);

        Ok(Self {
            name,
            target_description: TargetDescription::parse(target_description_block)?,
            logical_expression,
            subsigs,
        })
    }
}

impl<'p> Display for LogicalSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
rule {}
{{
    meta:
        original_ident: \"{}\"
        {}
    strings:
        \"{:?}\"
    condition:
        \"{:?}\"
}}",
            self.name.replace(".","_").replace("-","_"),
            self.name,
            self.target_description,
            self.subsigs,
            self.logical_expression
        )
    }
}
