use anyhow::{Context, Result};
use std::fmt::Display;

use crate::{ir, yara};

mod target_description;
use target_description::TargetDescription;

mod expression;
use expression::LogicalExpression;

mod subsig;
use subsig::Subsignature;

#[derive(Debug)]
pub struct LogicalSignature<'p> {
    pub name: &'p str,
    pub target_description: TargetDescription<'p>,
    pub logical_expression: LogicalExpression,
    pub subsigs: Vec<Subsignature<'p>>,
}

impl<'p> LogicalSignature<'p> {
    pub fn parse(sig: &'p str) -> Result<Self> {
        let mut parts = sig.splitn(4, ';');
        let name = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid signature: missing name"))?;
        let target_description_block = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid signature: missing target description"))?;
        let logical_expression = LogicalExpression::parse(
            parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("Invalid signature: missing expression"))?
                .to_string(),
        )
        .with_context(|| "Can't parse LogicalExpression")?;
        let subsig_block = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid signature: missing subsigs"))?;
        let subsigs = split_subsignatures(subsig_block)
            .into_iter()
            .map(Subsignature::parse)
            .collect::<Result<Vec<_>>>()
            .with_context(|| "Can't parse subsigs")?;

        Ok(Self {
            name,
            target_description: TargetDescription::parse(target_description_block)?,
            logical_expression,
            subsigs,
        })
    }

    pub fn to_ir(&self) -> ir::LogicalSignature {
        ir::LogicalSignature {
            name: self.name.to_string(),
            target_description: self.target_description.to_ir(),
            expression: self.logical_expression.to_ir(),
            subsignatures: self.subsigs.iter().map(Subsignature::to_ir).collect(),
        }
    }
}

fn split_subsignatures<'p>(input: &'p str) -> Vec<&'p str> {
    if input.is_empty() {
        return Vec::new();
    }

    let mut subsigs = Vec::new();
    let mut start = 0usize;
    let mut in_pcre = false;
    let mut escaped = false;

    for (idx, ch) in input.char_indices() {
        if in_pcre {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '/' {
                in_pcre = false;
            }
            continue;
        }

        match ch {
            '/' => {
                in_pcre = true;
            }
            ';' => {
                subsigs.push(&input[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }

    if start <= input.len() {
        subsigs.push(&input[start..]);
    }

    subsigs
}

impl<'p> Display for LogicalSignature<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match yara::lower_logical_signature(&self.to_ir()) {
            Ok(rule) => write!(f, "{}", rule),
            Err(_) => write!(f, "<invalid yara rule>"),
        }
    }
}
