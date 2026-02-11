use std::{
    collections::HashSet,
    fmt::{self, Display},
};

use anyhow::Result;

use crate::{
    ir,
    parser::{hash::HashSignature, logical::LogicalSignature},
};

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

pub fn render_hash_signature(value: &ir::HashSignature) -> String {
    let rule_name = normalize_rule_name(&value.name);
    let mut meta = format!("        original_ident = \"{}\"\n", value.name);
    if let Some(flevel) = value.min_flevel {
        meta.push_str(&format!("        min_flevel = \"{flevel}\"\n"));
    }

    match &value.source {
        ir::HashSource::File { size } => {
            let size_expr = match size {
                Some(size) => size.to_string(),
                None => "filesize".to_string(),
            };
            format!(
                "import \"hash\"\nrule {}\n{{\n    meta:\n{}\n    condition:\n        hash.{}(0, {}) == \"{}\"\n}}",
                rule_name,
                meta,
                hash_fn(&value.hash_type),
                size_expr,
                value.hash
            )
        }
        ir::HashSource::Section { size } => {
            let section_size = match size {
                Some(size) => size.to_string(),
                None => "*".to_string(),
            };
            meta.push_str(&format!(
                "        clamav_section_size = \"{section_size}\"\n"
            ));
            meta.push_str(&format!(
                "        clamav_hash_type = \"{}\"\n",
                hash_fn(&value.hash_type)
            ));
            meta.push_str("        clamav_unsupported = \"section_hash\"\n");

            format!(
                "rule {}\n{{\n    meta:\n{}\n    condition:\n        false\n}}",
                rule_name, meta
            )
        }
    }
}

pub fn lower_logical_signature(value: &ir::LogicalSignature) -> Result<YaraRule> {
    let mut meta = Vec::new();
    meta.push(YaraMeta::Entry {
        key: "original_ident".to_string(),
        value: value.name.to_string(),
    });

    if !value.target_description.raw.is_empty() {
        meta.push(YaraMeta::Entry {
            key: "clamav_target_description".to_string(),
            value: value.target_description.raw.to_string(),
        });
    }

    let subsigs = compact_whitespace(&format!("{:?}", value.subsignatures));
    if !subsigs.is_empty() {
        meta.push(YaraMeta::Entry {
            key: "clamav_subsigs".to_string(),
            value: subsigs,
        });
    }

    let (strings, id_map, mut notes) = lower_subsignatures(&value.subsignatures);
    let condition = lower_condition(&value.expression, &id_map, &mut notes);
    let strings = drop_unreferenced_strings(strings, &condition, &mut notes);

    if !notes.is_empty() {
        meta.push(YaraMeta::Entry {
            key: "clamav_lowering_notes".to_string(),
            value: notes.join(" | "),
        });
    }

    Ok(YaraRule {
        name: normalize_rule_name(&value.name),
        meta,
        strings,
        condition,
        imports: Vec::new(),
    })
}

fn lower_subsignatures(
    subsigs: &[ir::Subsignature],
) -> (Vec<YaraString>, Vec<Option<String>>, Vec<String>) {
    let mut strings = Vec::new();
    let mut id_map = Vec::with_capacity(subsigs.len());
    let mut notes = Vec::new();

    for (idx, subsig) in subsigs.iter().enumerate() {
        let id = format!("$s{idx}");
        match &subsig.pattern {
            ir::SubsignaturePattern::Hex(hex) if is_even_hex(hex) => {
                if !subsig.modifiers.is_empty() {
                    notes.push(format!(
                        "subsig[{idx}] ignored modifiers on hex: {}",
                        subsig_modifier_codes(&subsig.modifiers)
                    ));
                }
                let line = format!("{id} = {{ {} }}", format_hex_bytes(hex));
                strings.push(YaraString::Raw(line));
                id_map.push(Some(id));
            }
            ir::SubsignaturePattern::Hex(_) => {
                notes.push(format!("subsig[{idx}] skipped: invalid hex pattern"));
                id_map.push(None);
            }
            ir::SubsignaturePattern::Raw(raw) => {
                notes.push(format!(
                    "subsig[{idx}] skipped: unsupported raw/pcre pattern ({})",
                    compact_whitespace(raw)
                ));
                id_map.push(None);
            }
        }
    }

    (strings, id_map, notes)
}

fn lower_condition(
    expr: &ir::LogicalExpression,
    id_map: &[Option<String>],
    notes: &mut Vec<String>,
) -> String {
    match expr {
        ir::LogicalExpression::SubExpression(idx) => id_for(*idx, id_map, notes),
        ir::LogicalExpression::And(nodes) => {
            let parts: Vec<String> = nodes
                .iter()
                .map(|n| lower_condition(n, id_map, notes))
                .collect();
            join_condition(parts, "and")
        }
        ir::LogicalExpression::Or(nodes) => {
            let parts: Vec<String> = nodes
                .iter()
                .map(|n| lower_condition(n, id_map, notes))
                .collect();
            join_condition(parts, "or")
        }
        ir::LogicalExpression::MatchCount(inner, count) => {
            lower_count_at_least(*count, inner, id_map, notes)
        }
        ir::LogicalExpression::Gt(inner, count) => {
            lower_count_at_least(count.saturating_add(1), inner, id_map, notes)
        }
        ir::LogicalExpression::Lt(inner, count) => {
            if *count == 0 {
                notes.push("expression '<0' is impossible; lowered to false".to_string());
                return "false".to_string();
            }

            if let Some(set) = lower_count_set(inner, id_map, notes) {
                format!("not ({} of ({}))", count, set.join(", "))
            } else {
                "false".to_string()
            }
        }
        ir::LogicalExpression::MultiMatchCount(inner, min, max) => {
            if *min > *max {
                notes.push(format!(
                    "invalid match range (=): min {min} > max {max}; lowered to false"
                ));
                return "false".to_string();
            }

            if let Some(set) = lower_count_set(inner, id_map, notes) {
                let set_expr = set.join(", ");
                format!(
                    "({min} of ({set_expr})) and not ({} of ({set_expr}))",
                    max.saturating_add(1)
                )
            } else {
                "false".to_string()
            }
        }
        ir::LogicalExpression::MultiGt(inner, _, _)
        | ir::LogicalExpression::MultiLt(inner, _, _) => {
            notes.push(
                "multi-threshold comparator (>x,y / <x,y) not implemented yet; lowered to false"
                    .to_string(),
            );
            let _ = lower_count_set(inner, id_map, notes);
            "false".to_string()
        }
    }
}

fn lower_count_at_least(
    threshold: usize,
    inner: &ir::LogicalExpression,
    id_map: &[Option<String>],
    notes: &mut Vec<String>,
) -> String {
    if threshold == 0 {
        return "true".to_string();
    }

    if let Some(set) = lower_count_set(inner, id_map, notes) {
        format!("{threshold} of ({})", set.join(", "))
    } else {
        "false".to_string()
    }
}

fn lower_count_set(
    expr: &ir::LogicalExpression,
    id_map: &[Option<String>],
    notes: &mut Vec<String>,
) -> Option<Vec<String>> {
    let mut set = Vec::<String>::new();
    if collect_subexpr_terms(expr, id_map, notes, &mut set) {
        if set.is_empty() {
            notes.push("count expression had no resolvable subsigs; lowered to false".to_string());
            None
        } else {
            Some(set)
        }
    } else {
        notes.push(
            "count expression contains unsupported nested structure; lowered to false".to_string(),
        );
        None
    }
}

fn collect_subexpr_terms(
    expr: &ir::LogicalExpression,
    id_map: &[Option<String>],
    notes: &mut Vec<String>,
    out: &mut Vec<String>,
) -> bool {
    match expr {
        ir::LogicalExpression::SubExpression(idx) => {
            let id = id_for(*idx, id_map, notes);
            if id != "false" && !out.contains(&id) {
                out.push(id);
            }
            true
        }
        ir::LogicalExpression::And(nodes) | ir::LogicalExpression::Or(nodes) => nodes
            .iter()
            .all(|node| collect_subexpr_terms(node, id_map, notes, out)),
        _ => false,
    }
}

fn id_for(idx: usize, id_map: &[Option<String>], notes: &mut Vec<String>) -> String {
    match id_map.get(idx).and_then(|v| v.as_ref()) {
        Some(id) => id.to_string(),
        None => {
            notes.push(format!(
                "expression references unsupported/missing subsig index {idx}; lowered to false"
            ));
            "false".to_string()
        }
    }
}

fn join_condition(parts: Vec<String>, op: &str) -> String {
    if parts.is_empty() {
        return "false".to_string();
    }
    if parts.len() == 1 {
        return parts[0].clone();
    }

    format!("({})", parts.join(&format!(" {op} ")))
}

fn drop_unreferenced_strings(
    strings: Vec<YaraString>,
    condition: &str,
    notes: &mut Vec<String>,
) -> Vec<YaraString> {
    let referenced = referenced_identifiers(condition);

    let mut kept = Vec::new();
    let mut dropped = 0usize;

    for string in strings {
        let Some(id) = string_identifier(&string) else {
            kept.push(string);
            continue;
        };

        if referenced.contains(&id) {
            kept.push(string);
        } else {
            dropped += 1;
        }
    }

    if dropped > 0 {
        notes.push(format!(
            "dropped {dropped} unreferenced string pattern(s) to satisfy YARA compiler"
        ));
    }

    kept
}

fn referenced_identifiers(condition: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let chars: Vec<char> = condition.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == '$' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            if i > start + 1 {
                out.insert(chars[start..i].iter().collect());
            }
            continue;
        }
        i += 1;
    }

    out
}

fn string_identifier(string: &YaraString) -> Option<String> {
    match string {
        YaraString::Raw(raw) => raw.split_whitespace().next().map(|s| s.to_string()),
    }
}

fn is_even_hex(input: &str) -> bool {
    !input.is_empty() && input.len() % 2 == 0 && input.chars().all(|c| c.is_ascii_hexdigit())
}

fn format_hex_bytes(input: &str) -> String {
    let mut out = String::new();
    for (idx, chunk) in input.as_bytes().chunks(2).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(&String::from_utf8_lossy(chunk).to_uppercase());
    }
    out
}

fn subsig_modifier_codes(modifiers: &[ir::SubsignatureModifier]) -> String {
    modifiers
        .iter()
        .map(|m| match m {
            ir::SubsignatureModifier::CaseInsensitive => "i".to_string(),
            ir::SubsignatureModifier::Wide => "w".to_string(),
            ir::SubsignatureModifier::Fullword => "f".to_string(),
            ir::SubsignatureModifier::Ascii => "a".to_string(),
            ir::SubsignatureModifier::Unknown(c) => c.to_string(),
        })
        .collect::<Vec<_>>()
        .join("")
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
                        writeln!(f, "        {}", raw)?;
                    }
                }
            }
        }

        writeln!(f, "    condition:")?;
        writeln!(f, "        {}", self.condition)?;
        write!(f, "}}")?;

        Ok(())
    }
}

impl TryFrom<&ir::LogicalSignature> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: &ir::LogicalSignature) -> Result<Self> {
        lower_logical_signature(value)
    }
}

impl TryFrom<ir::LogicalSignature> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: ir::LogicalSignature) -> Result<Self> {
        YaraRule::try_from(&value)
    }
}

impl<'p> TryFrom<&LogicalSignature<'p>> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: &LogicalSignature<'p>) -> Result<Self> {
        let ir = value.to_ir();
        YaraRule::try_from(&ir)
    }
}

impl<'p> TryFrom<LogicalSignature<'p>> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: LogicalSignature<'p>) -> Result<Self> {
        YaraRule::try_from(&value)
    }
}

impl<'p> From<&HashSignature<'p>> for ir::HashSignature {
    fn from(value: &HashSignature<'p>) -> Self {
        value.to_ir()
    }
}

fn normalize_rule_name(input: &str) -> String {
    input.replace('.', "_").replace('-', "_")
}

fn hash_fn(hash_type: &ir::HashType) -> &'static str {
    match hash_type {
        ir::HashType::Md5 => "md5",
        ir::HashType::Sha1 => "sha1",
        ir::HashType::Sha256 => "sha256",
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
