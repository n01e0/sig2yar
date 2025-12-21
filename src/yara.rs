use std::fmt::{self, Display};

use anyhow::Result;

use crate::parser::logical::LogicalSignature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraRule {
    pub name: String,
    pub meta: Vec<YaraMeta>,
    pub strings: Vec<YaraString>,
    pub condition: String,
    pub imports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaraMeta {
    Entry { key: String, value: String },
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaraString {
    Raw(String),
}

impl Display for YaraRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.imports.is_empty() {
            for import in &self.imports {
                writeln!(f, "import \"{}\"", import)?;
            }
        }

        write!(f, "\nrule {}", self.name)?;
        writeln!(f, "\n{{")?;

        if !self.meta.is_empty() {
            writeln!(f, "    meta:")?;
            for meta in &self.meta {
                match meta {
                    YaraMeta::Entry { key, value } => {
                        writeln!(f, "        {} = \"{}\"", key, escape_yara_string(value))?;
                    }
                    YaraMeta::Raw(raw) => {
                        write!(f, "{}", raw)?;
                        if !raw.ends_with('\n') {
                            writeln!(f)?;
                        }
                    }
                }
            }
        }

        if !self.strings.is_empty() {
            writeln!(f, "    strings:")?;
            for string in &self.strings {
                match string {
                    YaraString::Raw(raw) => {
                        writeln!(f, "        \"{}\"", raw)?;
                    }
                }
            }
        }

        writeln!(f, "    condition:")?;
        writeln!(f, "        \"{}\"", self.condition)?;
        write!(f, "}}")?;

        Ok(())
    }
}

impl<'p> TryFrom<&LogicalSignature<'p>> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: &LogicalSignature<'p>) -> Result<Self> {
        let mut meta = Vec::new();
        meta.push(YaraMeta::Entry {
            key: "original_ident".to_string(),
            value: value.name.to_string(),
        });

        let target_description = compact_whitespace(&value.target_description.to_string());
        if !target_description.is_empty() {
            meta.push(YaraMeta::Entry {
                key: "clamav_target_description".to_string(),
                value: target_description,
            });
        }

        let subsigs = compact_whitespace(&format!("{:?}", value.subsigs));
        if !subsigs.is_empty() {
            meta.push(YaraMeta::Entry {
                key: "clamav_subsigs".to_string(),
                value: subsigs,
            });
        }

        Ok(YaraRule {
            name: value.name.replace('.', "_").replace('-', "_"),
            meta,
            strings: Vec::new(),
            condition: "true".to_string(),
            imports: Vec::new(),
        })
    }
}

impl<'p> TryFrom<LogicalSignature<'p>> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: LogicalSignature<'p>) -> Result<Self> {
        YaraRule::try_from(&value)
    }
}

fn escape_yara_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn compact_whitespace(input: &str) -> String {
    input
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
