use std::{
    collections::HashSet,
    fmt::{self, Display},
};

use anyhow::Result;

use crate::{
    ir,
    parser::{hash::HashSignature, logical::LogicalSignature, ndb::NdbSignature},
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

pub fn render_ndb_signature(value: &ir::NdbSignature) -> String {
    lower_ndb_signature(value).to_string()
}

pub fn lower_ndb_signature(value: &ir::NdbSignature) -> YaraRule {
    let mut meta = Vec::new();
    let mut notes = Vec::new();
    let mut imports = Vec::new();

    meta.push(YaraMeta::Entry {
        key: "original_ident".to_string(),
        value: value.name.to_string(),
    });
    meta.push(YaraMeta::Entry {
        key: "clamav_target_type".to_string(),
        value: value.target_type.to_string(),
    });
    meta.push(YaraMeta::Entry {
        key: "clamav_offset".to_string(),
        value: value.offset.to_string(),
    });
    meta.push(YaraMeta::Entry {
        key: "clamav_body_len".to_string(),
        value: value.body.len().to_string(),
    });
    meta.push(YaraMeta::Entry {
        key: "clamav_body_preview".to_string(),
        value: preview_for_meta(&value.body, 128),
    });

    if let Some(min) = value.min_flevel {
        meta.push(YaraMeta::Entry {
            key: "min_flevel".to_string(),
            value: min.to_string(),
        });
    }
    if let Some(max) = value.max_flevel {
        meta.push(YaraMeta::Entry {
            key: "max_flevel".to_string(),
            value: max.to_string(),
        });
    }

    let mut strings = Vec::new();

    let condition = match lower_ndb_body_pattern(&value.body, &mut notes) {
        Some(body) => {
            let id = "$a";
            strings.push(YaraString::Raw(format!("{id} = {{ {body} }}")));

            let mut parts = vec![id.to_string()];

            if let Some(target_expr) = lower_ndb_target_condition(&value.target_type, &mut notes) {
                parts.push(format!("({target_expr})"));
            }

            match lower_ndb_offset_condition(&value.offset, id, &mut imports, &mut notes) {
                Some(offset_expr) => parts.push(format!("({offset_expr})")),
                None if value.offset == "*" => {}
                None => {
                    notes.push(format!(
                        "ndb offset unsupported: {} (forcing condition=false)",
                        value.offset
                    ));
                    parts.push("false".to_string());
                }
            }

            join_condition(parts, "and")
        }
        None => {
            notes.push("ndb body lowering failed (forcing condition=false)".to_string());
            "false".to_string()
        }
    };

    if !notes.is_empty() {
        meta.push(YaraMeta::Entry {
            key: "clamav_lowering_notes".to_string(),
            value: notes.join(" | "),
        });
    }

    YaraRule {
        name: normalize_rule_name(&value.name),
        meta,
        strings,
        condition,
        imports,
    }
}

fn lower_ndb_body_pattern(body: &str, notes: &mut Vec<String>) -> Option<String> {
    let chars: Vec<char> = body.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];

        if ch.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        if ch.is_ascii_hexdigit() || ch == '?' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_hexdigit() || chars[i] == '?') {
                i += 1;
            }

            let run: String = chars[start..i].iter().collect();
            if run.len() % 2 != 0 {
                notes.push(format!("ndb body contains odd-length byte run: {run}"));
                return None;
            }

            for chunk in run.as_bytes().chunks(2) {
                let token = std::str::from_utf8(chunk).ok()?;
                if !is_valid_ndb_byte_token(token) {
                    notes.push(format!("ndb body contains invalid byte token: {token}"));
                    return None;
                }
                tokens.push(token.to_ascii_uppercase());
            }
            continue;
        }

        match ch {
            '*' => {
                tokens.push("[-]".to_string());
                i += 1;
            }
            '{' => {
                let end = find_matching(&chars, i, '}')?;
                let inner: String = chars[i + 1..end].iter().collect();
                let jump = lower_ndb_curly_jump(inner.trim(), notes)?;
                tokens.push(jump);
                i = end + 1;
            }
            '[' => {
                let end = find_matching(&chars, i, ']')?;
                let inner: String = chars[i + 1..end].iter().collect();
                if !is_valid_ndb_square(inner.trim()) {
                    notes.push(format!(
                        "ndb body contains unsupported [] token: [{}]",
                        inner
                    ));
                    return None;
                }
                tokens.push(format!("[{}]", inner.trim()));
                i = end + 1;
            }
            '(' | ')' | '|' => {
                tokens.push(ch.to_string());
                i += 1;
            }
            _ => {
                notes.push(format!("ndb body contains unsupported character: {ch}"));
                return None;
            }
        }
    }

    if tokens.is_empty() {
        notes.push("ndb body is empty after tokenization".to_string());
        return None;
    }

    if tokens.first().is_some_and(|token| is_ndb_jump_token(token))
        || tokens.last().is_some_and(|token| is_ndb_jump_token(token))
    {
        notes.push("ndb body starts/ends with jump token unsupported by YARA".to_string());
        return None;
    }

    Some(tokens.join(" "))
}

fn lower_ndb_target_condition(target_type: &str, notes: &mut Vec<String>) -> Option<String> {
    match target_type {
        "0" => None,
        "1" => Some("uint16(0) == 0x5A4D".to_string()), // MZ/PE
        "2" => Some("uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1".to_string()), // OLE2
        "3" => {
            notes.push(
                "ndb target_type=3 (HTML normalized) lowered with structural HTML heuristic"
                    .to_string(),
            );
            Some(ndb_html_target_condition())
        }
        "4" => {
            notes.push(
                "ndb target_type=4 (mail) lowered with header-prefix heuristic".to_string(),
            );
            Some(ndb_mail_target_condition())
        }
        "5" => Some(ndb_graphics_target_condition()),
        "6" => Some("uint32(0) == 0x464C457F".to_string()), // ELF
        "7" => Some(ndb_ascii_target_condition()),
        "9" => Some(
            "(uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA or uint32(0) == 0xCAFEBABE)".to_string(),
        ), // Mach-O and FAT
        "10" => Some("uint32(0) == 0x46445025".to_string()), // %PDF
        "11" => Some(
            "((uint8(0) == 0x46 or uint8(0) == 0x43 or uint8(0) == 0x5A) and uint8(1) == 0x57 and uint8(2) == 0x53)".to_string(),
        ), // FWS/CWS/ZWS
        "12" => Some("uint32(0) == 0xBEBAFECA".to_string()), // CAFEBABE
        other => {
            notes.push(format!(
                "ndb target_type={other} is not yet constrained in condition"
            ));
            None
        }
    }
}

fn ndb_ascii_predicate(var: &str) -> String {
    format!(
        "({var} == 0x09 or {var} == 0x0A or {var} == 0x0D or ({var} >= 0x20 and {var} <= 0x7E))"
    )
}

fn ndb_ascii_target_condition() -> String {
    let pred = ndb_ascii_predicate("uint8(i)");
    format!(
        "filesize > 0 and ((filesize <= 4096 and for all i in (0..filesize-1) : ({pred})) or (filesize > 4096 and for all i in (0..4095) : ({pred})))"
    )
}

fn ndb_html_target_condition() -> String {
    let ascii_pred = ndb_ascii_predicate("uint8(i)");
    format!(
        "filesize > 0 and ((filesize <= 4096 and for all i in (0..filesize-1) : ({ascii_pred}) and for any j in (0..filesize-1) : (uint8(j) == 0x3C) and for any k in (0..filesize-1) : (uint8(k) == 0x3E)) or (filesize > 4096 and for all i in (0..4095) : ({ascii_pred}) and for any j in (0..4095) : (uint8(j) == 0x3C) and for any k in (0..4095) : (uint8(k) == 0x3E)))"
    )
}

fn ndb_mail_target_condition() -> String {
    "filesize > 5 and (uint32(0) == 0x6D6F7246 or uint32(0) == 0x65636552 or uint32(0) == 0x6A627553 or uint32(0) == 0x65746144 or uint32(0) == 0x454D494D or uint32(0) == 0x75746552)"
        .to_string()
}

fn ndb_graphics_target_condition() -> String {
    "(uint32(0) == 0x474E5089 or uint16(0) == 0xD8FF or uint32(0) == 0x38464947 or uint16(0) == 0x4D42 or uint32(0) == 0x002A4949 or uint32(0) == 0x2A004D4D or (filesize >= 12 and uint32(0) == 0x0C000000 and uint32(4) == 0x2020506A and uint32(8) == 0x0A870A0D))"
        .to_string()
}

fn lower_ndb_offset_condition(
    offset: &str,
    id: &str,
    imports: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Option<String> {
    if offset == "*" {
        return None;
    }

    if let Some((start, end)) = parse_u64_pair(offset) {
        return Some(format!("{id} in ({start}..{end})"));
    }

    if let Ok(value) = offset.parse::<u64>() {
        return Some(format!("{id} at {value}"));
    }

    if let Some((delta, range)) = parse_ep_offset(offset) {
        ensure_import(imports, "pe");
        let start = apply_signed_delta("pe.entry_point", delta);
        return Some(match range {
            Some(width) => {
                let end = apply_signed_delta(&start, width);
                ndb_occurrence_in_expr(id, &start, &end)
            }
            None => ndb_occurrence_at_expr(id, &start),
        });
    }

    if let Some((section_idx, delta, range)) = parse_section_offset(offset) {
        ensure_import(imports, "pe");
        let base = format!("pe.sections[{section_idx}].raw_data_offset");
        let start = apply_unsigned_delta(&base, delta);
        let match_expr = match range {
            Some(width) => {
                let end = apply_unsigned_delta(&start, width);
                ndb_occurrence_in_expr(id, &start, &end)
            }
            None => ndb_occurrence_at_expr(id, &start),
        };
        return Some(format!(
            "pe.number_of_sections > {section_idx} and ({match_expr})"
        ));
    }

    if let Some((delta, range)) = parse_last_section_offset(offset) {
        ensure_import(imports, "pe");
        let base = "pe.sections[pe.number_of_sections - 1].raw_data_offset";
        let start = apply_unsigned_delta(base, delta);
        let match_expr = match range {
            Some(width) => {
                let end = apply_unsigned_delta(&start, width);
                ndb_occurrence_in_expr(id, &start, &end)
            }
            None => ndb_occurrence_at_expr(id, &start),
        };
        return Some(format!("pe.number_of_sections > 0 and ({match_expr})"));
    }

    if let Some(section_idx) = parse_section_end_offset(offset) {
        ensure_import(imports, "pe");
        let at = format!(
            "pe.sections[{section_idx}].raw_data_offset + pe.sections[{section_idx}].raw_data_size"
        );
        let match_expr = ndb_occurrence_at_expr(id, &at);
        return Some(format!(
            "pe.number_of_sections > {section_idx} and ({match_expr})"
        ));
    }

    if let Some((delta, range)) = parse_eof_offset(offset) {
        let start = apply_signed_delta("filesize", delta);
        return Some(match range {
            Some(width) => {
                let end = apply_signed_delta(&start, width);
                ndb_occurrence_in_expr(id, &start, &end)
            }
            None => ndb_occurrence_at_expr(id, &start),
        });
    }

    notes.push(format!("ndb offset format is unsupported: {offset}"));
    None
}

fn ensure_import(imports: &mut Vec<String>, name: &str) {
    if !imports.iter().any(|v| v == name) {
        imports.push(name.to_string());
    }
}

fn ndb_occurrence_at_expr(id: &str, at: &str) -> String {
    let core = id.strip_prefix('$').unwrap_or(id);
    format!("for any i in (1..#{core}) : ( @{core}[i] == {at} )")
}

fn ndb_occurrence_in_expr(id: &str, start: &str, end: &str) -> String {
    let core = id.strip_prefix('$').unwrap_or(id);
    format!("for any i in (1..#{core}) : ( @{core}[i] >= {start} and @{core}[i] <= {end} )")
}

fn apply_signed_delta(base: &str, delta: i64) -> String {
    if delta >= 0 {
        format!("{base} + {delta}")
    } else {
        format!("{base} - {}", -delta)
    }
}

fn apply_unsigned_delta(base: &str, delta: u64) -> String {
    if delta == 0 {
        base.to_string()
    } else {
        format!("{base} + {delta}")
    }
}

fn is_valid_ndb_byte_token(token: &str) -> bool {
    if token.len() != 2 {
        return false;
    }
    token.chars().all(|c| c.is_ascii_hexdigit() || c == '?')
}

fn is_ndb_jump_token(token: &str) -> bool {
    token.starts_with('[') && token.ends_with(']')
}

fn is_valid_ndb_square(value: &str) -> bool {
    if value == "-" {
        return true;
    }

    if let Some((lhs, rhs)) = value.split_once('-') {
        if lhs.is_empty() && rhs.is_empty() {
            return true;
        }
        if lhs.is_empty() {
            return rhs.chars().all(|c| c.is_ascii_digit());
        }
        if rhs.is_empty() {
            return lhs.chars().all(|c| c.is_ascii_digit());
        }
        return lhs.chars().all(|c| c.is_ascii_digit()) && rhs.chars().all(|c| c.is_ascii_digit());
    }

    value.chars().all(|c| c.is_ascii_digit())
}

fn lower_ndb_curly_jump(value: &str, notes: &mut Vec<String>) -> Option<String> {
    if let Ok(num) = value.parse::<i64>() {
        if num >= 0 {
            return Some(format!("[{num}]"));
        }

        let width = num.unsigned_abs();
        return Some(format!("[0-{width}]"));
    }

    if let Some((lhs, rhs)) = value.split_once('-') {
        let lhs = lhs.trim();
        let rhs = rhs.trim();

        if !lhs.is_empty() && rhs.is_empty() {
            let start = lhs.parse::<u64>().ok()?;
            return Some(format!("[{start}-]"));
        }

        let start = lhs.parse::<i64>().ok()?;
        let end = rhs.parse::<i64>().ok()?;

        if start >= 0 && end >= 0 {
            if start <= end {
                return Some(format!("[{start}-{end}]"));
            }
            notes.push(format!(
                "ndb range jump with descending bounds {{{value}}} treated as [{end}-{start}]"
            ));
            return Some(format!("[{end}-{start}]"));
        }

        let width = start.unsigned_abs().max(end.unsigned_abs());
        notes.push(format!(
            "ndb negative range jump {{{value}}} approximated to [0-{width}]"
        ));
        return Some(format!("[0-{width}]"));
    }

    None
}

fn find_matching(chars: &[char], open_idx: usize, closing: char) -> Option<usize> {
    for (idx, ch) in chars.iter().enumerate().skip(open_idx + 1) {
        if *ch == closing {
            return Some(idx);
        }
    }
    None
}

fn parse_u64_pair(input: &str) -> Option<(u64, u64)> {
    let (lhs, rhs) = input.split_once(',')?;
    let start = lhs.parse::<u64>().ok()?;
    let end = rhs.parse::<u64>().ok()?;
    Some((start.min(end), start.max(end)))
}

fn parse_ep_offset(input: &str) -> Option<(i64, Option<i64>)> {
    let rest = input.strip_prefix("EP")?;
    let (delta_str, range_str) = match rest.split_once(',') {
        Some((delta, range)) => (delta, Some(range)),
        None => (rest, None),
    };

    let delta = parse_signed_with_plus(delta_str)?;
    let range = range_str.and_then(|v| v.parse::<i64>().ok());
    Some((delta, range))
}

fn parse_section_offset(input: &str) -> Option<(u64, u64, Option<u64>)> {
    let rest = input.strip_prefix('S')?;
    if rest.starts_with('L') || rest.starts_with('E') {
        return None;
    }

    let (idx, tail) = rest.split_once('+')?;
    let section_idx = idx.parse::<u64>().ok()?;
    let (delta, range) = match tail.split_once(',') {
        Some((delta, range)) => (delta.parse::<u64>().ok()?, Some(range.parse::<u64>().ok()?)),
        None => (tail.parse::<u64>().ok()?, None),
    };

    Some((section_idx, delta, range))
}

fn parse_last_section_offset(input: &str) -> Option<(u64, Option<u64>)> {
    let rest = input.strip_prefix("SL+")?;
    let (delta, range) = match rest.split_once(',') {
        Some((delta, range)) => (delta.parse::<u64>().ok()?, Some(range.parse::<u64>().ok()?)),
        None => (rest.parse::<u64>().ok()?, None),
    };
    Some((delta, range))
}

fn parse_section_end_offset(input: &str) -> Option<u64> {
    let idx = input.strip_prefix("SE")?;
    idx.parse::<u64>().ok()
}

fn parse_eof_offset(input: &str) -> Option<(i64, Option<i64>)> {
    let rest = input.strip_prefix("EOF")?;
    let (delta_str, range_str) = match rest.split_once(',') {
        Some((delta, range)) => (delta, Some(range)),
        None => (rest, None),
    };

    let delta = if delta_str.is_empty() {
        0
    } else {
        parse_signed_with_plus(delta_str)?
    };

    let range = range_str.and_then(|v| v.parse::<i64>().ok());
    Some((delta, range))
}

fn parse_signed_with_plus(input: &str) -> Option<i64> {
    if let Some(value) = input.strip_prefix('+') {
        return value.parse::<i64>().ok();
    }
    input.parse::<i64>().ok()
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
            ir::SubsignaturePattern::Raw(raw) => match lower_raw_or_pcre_subsignature(
                idx,
                &id,
                raw,
                &subsig.modifiers,
                &id_map,
                &mut notes,
            ) {
                RawSubsigLowering::String(line) => {
                    strings.push(YaraString::Raw(line));
                    id_map.push(Some(id));
                }
                RawSubsigLowering::Alias(alias) => {
                    id_map.push(Some(alias));
                }
                RawSubsigLowering::Skip => {
                    id_map.push(None);
                }
            },
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

enum RawSubsigLowering {
    String(String),
    Alias(String),
    Skip,
}

fn lower_raw_or_pcre_subsignature(
    idx: usize,
    id: &str,
    raw: &str,
    modifiers: &[ir::SubsignatureModifier],
    known_ids: &[Option<String>],
    notes: &mut Vec<String>,
) -> RawSubsigLowering {
    if raw.trim().is_empty() {
        notes.push(format!("subsig[{idx}] skipped: empty raw pattern"));
        return RawSubsigLowering::Skip;
    }

    if let Some(trigger_idx) = parse_byte_comparison_trigger(raw) {
        if let Some(Some(alias)) = known_ids.get(trigger_idx) {
            notes.push(format!(
                "subsig[{idx}] byte_comparison lowered as alias to subsig[{trigger_idx}]"
            ));
            return RawSubsigLowering::Alias(alias.clone());
        }

        notes.push(format!(
            "subsig[{idx}] byte_comparison trigger {trigger_idx} unresolved; fallback to literal"
        ));
    }

    if let Some(macro_idx) = parse_macro_reference(raw) {
        if let Some(Some(alias)) = known_ids.get(macro_idx) {
            notes.push(format!(
                "subsig[{idx}] macro lowered as alias to subsig[{macro_idx}]"
            ));
            return RawSubsigLowering::Alias(alias.clone());
        }

        notes.push(format!(
            "subsig[{idx}] macro reference {macro_idx} unresolved; fallback to literal"
        ));
    }

    if is_fuzzy_img_pattern(raw) {
        notes.push(format!(
            "subsig[{idx}] fuzzy_img lowering is approximate (literal fallback)"
        ));
    }

    let mut string_mods = StringModifierSet::default();
    for modifier in modifiers {
        match modifier {
            ir::SubsignatureModifier::CaseInsensitive => string_mods.nocase = true,
            ir::SubsignatureModifier::Wide => string_mods.wide = true,
            ir::SubsignatureModifier::Fullword => string_mods.fullword = true,
            ir::SubsignatureModifier::Ascii => string_mods.ascii = true,
            ir::SubsignatureModifier::Unknown(ch) => {
                notes.push(format!("subsig[{idx}] ignored unknown modifier '{}'", ch));
            }
        }
    }

    if let Some(pcre) = parse_pcre_like(raw) {
        if pcre.has_trigger_prefix {
            notes.push(format!(
                "subsig[{idx}] pcre trigger prefix ignored during lowering"
            ));
        }

        for flag in pcre.flags.chars() {
            match flag {
                'i' => string_mods.nocase = true,
                // these need dedicated semantic mapping; keep explicit note for now
                'g' | 'r' | 'E' | 's' | 'm' | 'e' | 'a' | 'd' | 'U' => notes.push(format!(
                    "subsig[{idx}] pcre flag '{}' is not mapped yet",
                    flag
                )),
                other => notes.push(format!(
                    "subsig[{idx}] unknown pcre flag '{}' ignored",
                    other
                )),
            }
        }

        let render_mods = render_string_modifiers(&string_mods);
        return RawSubsigLowering::String(format!("{id} = /{}/{}", pcre.pattern, render_mods));
    }

    let escaped = escape_yara_string(raw);
    let render_mods = render_string_modifiers(&string_mods);
    RawSubsigLowering::String(format!("{id} = \"{}\"{}", escaped, render_mods))
}

#[derive(Default)]
struct StringModifierSet {
    nocase: bool,
    wide: bool,
    ascii: bool,
    fullword: bool,
}

fn render_string_modifiers(mods: &StringModifierSet) -> String {
    let mut out = String::new();

    if mods.nocase {
        out.push_str(" nocase");
    }
    if mods.wide {
        out.push_str(" wide");
    }
    if mods.ascii {
        out.push_str(" ascii");
    }
    if mods.fullword {
        out.push_str(" fullword");
    }

    out
}

fn parse_byte_comparison_trigger(raw: &str) -> Option<usize> {
    let open = raw.find('(')?;
    if open == 0 || !raw.ends_with(')') || !raw.contains('#') {
        return None;
    }

    let trigger = &raw[..open];
    if !trigger.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    trigger.parse::<usize>().ok()
}

fn parse_macro_reference(raw: &str) -> Option<usize> {
    if !raw.starts_with("${") || !raw.ends_with('$') {
        return None;
    }

    let close = raw.find('}')?;
    if close + 2 > raw.len() {
        return None;
    }

    let ref_part = &raw[close + 1..raw.len() - 1];
    if ref_part.is_empty() || !ref_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    ref_part.parse::<usize>().ok()
}

fn is_fuzzy_img_pattern(raw: &str) -> bool {
    raw.starts_with("fuzzy_img#")
}

struct ParsedPcre<'a> {
    pattern: &'a str,
    flags: &'a str,
    has_trigger_prefix: bool,
}

fn parse_pcre_like(raw: &str) -> Option<ParsedPcre<'_>> {
    let start = raw.find('/')?;
    let prefix = raw[..start].trim();

    let mut escaped = false;
    let mut end = None;
    for (offset, ch) in raw[start + 1..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '/' => {
                end = Some(start + 1 + offset);
                break;
            }
            _ => {}
        }
    }

    let end = end?;
    let pattern = &raw[start + 1..end];
    let flags = raw[end + 1..].trim();

    if flags.is_empty() {
        return Some(ParsedPcre {
            pattern,
            flags: "",
            has_trigger_prefix: !prefix.is_empty(),
        });
    }

    if !flags.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    Some(ParsedPcre {
        pattern,
        flags,
        has_trigger_prefix: !prefix.is_empty(),
    })
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

impl TryFrom<&ir::NdbSignature> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: &ir::NdbSignature) -> Result<Self> {
        Ok(lower_ndb_signature(value))
    }
}

impl TryFrom<ir::NdbSignature> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: ir::NdbSignature) -> Result<Self> {
        YaraRule::try_from(&value)
    }
}

impl<'p> TryFrom<&NdbSignature<'p>> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: &NdbSignature<'p>) -> Result<Self> {
        let ir = value.to_ir();
        YaraRule::try_from(&ir)
    }
}

impl<'p> TryFrom<NdbSignature<'p>> for YaraRule {
    type Error = anyhow::Error;

    fn try_from(value: NdbSignature<'p>) -> Result<Self> {
        YaraRule::try_from(&value)
    }
}

impl<'p> From<&HashSignature<'p>> for ir::HashSignature {
    fn from(value: &HashSignature<'p>) -> Self {
        value.to_ir()
    }
}

impl<'p> From<&NdbSignature<'p>> for ir::NdbSignature {
    fn from(value: &NdbSignature<'p>) -> Self {
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

fn preview_for_meta(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }

    let mut out = String::with_capacity(max_chars + 16);
    for (i, ch) in input.chars().enumerate() {
        if i >= max_chars {
            break;
        }
        out.push(ch);
    }
    out.push_str("...(truncated)");
    out
}

fn compact_whitespace(input: &str) -> String {
    input
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
