use std::{
    collections::HashSet,
    fmt::{self, Display},
};

use anyhow::Result;

use crate::{
    ir,
    parser::{
        hash::HashSignature,
        logical::{parse_expression_to_ir, LogicalSignature},
        ndb::NdbSignature,
    },
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
                "ndb target_type=4 (mail) lowered with strict multi-header heuristic"
                    .to_string(),
            );
            Some(ndb_mail_target_condition())
        }
        "5" => Some(ndb_graphics_target_condition()),
        "6" => Some("uint32(0) == 0x464C457F".to_string()), // ELF
        "7" => {
            notes.push(
                "ndb target_type=7 (ascii) lowered with full-file printable+alpha heuristic"
                    .to_string(),
            );
            Some(ndb_ascii_target_condition())
        }
        "8" => {
            notes.push(
                "ndb target_type=8 is reserved/unused; constrained to false for safety"
                    .to_string(),
            );
            Some("false".to_string())
        }
        "9" => Some(
            "(uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA or uint32(0) == 0xCAFEBABE)".to_string(),
        ), // Mach-O and FAT
        "10" => Some("uint32(0) == 0x46445025".to_string()), // %PDF
        "11" => Some(
            "((uint8(0) == 0x46 or uint8(0) == 0x43 or uint8(0) == 0x5A) and uint8(1) == 0x57 and uint8(2) == 0x53)".to_string(),
        ), // FWS/CWS/ZWS
        "12" => Some("uint32(0) == 0xBEBAFECA".to_string()), // CAFEBABE
        other => {
            if other.parse::<u32>().is_ok_and(|v| v >= 13) {
                notes.push(format!(
                    "ndb target_type={other} unsupported (13+); constrained to false for safety"
                ));
                Some("false".to_string())
            } else {
                notes.push(format!(
                    "ndb target_type={other} is invalid/unknown; constrained to false for safety"
                ));
                Some("false".to_string())
            }
        }
    }
}

fn ndb_ascii_predicate(var: &str) -> String {
    format!(
        "({var} == 0x09 or {var} == 0x0A or {var} == 0x0D or ({var} >= 0x20 and {var} <= 0x7E))"
    )
}

fn ndb_ascii_alpha_predicate(var: &str) -> String {
    format!("(({var} >= 0x41 and {var} <= 0x5A) or ({var} >= 0x61 and {var} <= 0x7A))")
}

fn ndb_ascii_target_condition() -> String {
    let pred = ndb_ascii_predicate("uint8(i)");
    let alpha = ndb_ascii_alpha_predicate("uint8(j)");
    format!(
        "filesize > 0 and for all i in (0..filesize-1) : ({pred}) and for any j in (0..filesize-1) : ({alpha})"
    )
}

fn ndb_html_target_condition() -> String {
    let ascii_pred = ndb_ascii_predicate("uint8(i)");
    let root_markers = ["<html", "<!doctype"];
    let close_markers = ["</html", "</body", "</head"];

    let root_small =
        ndb_any_prefix_in_window_condition(&root_markers, "r", "filesize-1", "filesize");
    let root_large = ndb_any_prefix_in_window_condition(&root_markers, "r", "511", "512");

    let close_small =
        ndb_any_prefix_in_window_condition(&close_markers, "c", "filesize-1", "filesize");
    let close_large = ndb_any_prefix_in_window_condition(&close_markers, "c", "4095", "4096");

    let root_before_close_small = ndb_any_prefix_before_separator_in_window_condition(
        &root_markers,
        &close_markers,
        "r",
        "c",
        "filesize-1",
        "filesize",
    );
    let root_before_close_large = ndb_any_prefix_before_separator_in_window_condition(
        &root_markers,
        &close_markers,
        "r",
        "c",
        "4095",
        "4096",
    );

    format!(
        "filesize > 0 and ((filesize <= 4096 and for all i in (0..filesize-1) : ({ascii_pred}) and for any j in (0..filesize-1) : (uint8(j) == 0x3C) and for any k in (0..filesize-1) : (uint8(k) == 0x3E) and {root_small} and {close_small} and {root_before_close_small}) or (filesize > 4096 and for all i in (0..4095) : ({ascii_pred}) and for any j in (0..4095) : (uint8(j) == 0x3C) and for any k in (0..4095) : (uint8(k) == 0x3E) and {root_large} and {close_large} and {root_before_close_large}))"
    )
}

fn ndb_mail_target_condition() -> String {
    let ascii_pred = ndb_ascii_predicate("uint8(i)");

    let start_headers = ["From:", "Received:", "Return-Path:"];
    let secondary_headers = [
        "Subject:",
        "Date:",
        "To:",
        "Cc:",
        "MIME-Version:",
        "Content-Type:",
        "Message-Id:",
    ];
    let separators = ["\r\n\r\n", "\n\n"];

    let header_exprs = start_headers
        .iter()
        .map(|header| ndb_ascii_prefix_at_offset_condition(header, "0"))
        .collect::<Vec<_>>();

    let secondary_before_separator_small = ndb_any_prefix_before_separator_in_window_condition(
        &secondary_headers,
        &separators,
        "h",
        "s",
        "filesize-1",
        "filesize",
    );
    let secondary_before_separator_large = ndb_any_prefix_before_separator_in_window_condition(
        &secondary_headers,
        &separators,
        "h",
        "s",
        "4095",
        "4096",
    );

    format!(
        "filesize > 0 and ((filesize <= 4096 and for all i in (0..filesize-1) : ({ascii_pred}) and ({}) and {secondary_before_separator_small}) or (filesize > 4096 and for all i in (0..4095) : ({ascii_pred}) and ({}) and {secondary_before_separator_large}))",
        header_exprs.join(" or "),
        header_exprs.join(" or "),
    )
}

fn ndb_any_prefix_in_window_condition(
    prefixes: &[&str],
    idx_var: &str,
    window_end: &str,
    size_limit: &str,
) -> String {
    let clauses = prefixes
        .iter()
        .map(|prefix| {
            let len = prefix.len();
            let prefix_match = ndb_ascii_prefix_at_offset_condition(prefix, idx_var);
            format!("({idx_var} + {len} <= {size_limit} and {prefix_match})")
        })
        .collect::<Vec<_>>()
        .join(" or ");

    format!("for any {idx_var} in (0..{window_end}) : ({clauses})")
}

fn ndb_any_prefix_before_separator_in_window_condition(
    prefixes: &[&str],
    separators: &[&str],
    prefix_var: &str,
    separator_var: &str,
    window_end: &str,
    size_limit: &str,
) -> String {
    let prefix_clauses = prefixes
        .iter()
        .map(|prefix| {
            let len = prefix.len();
            let prefix_match = ndb_ascii_prefix_at_offset_condition(prefix, prefix_var);
            format!("({prefix_var} + {len} <= {separator_var} and {prefix_match})")
        })
        .collect::<Vec<_>>()
        .join(" or ");

    let separator_clauses = separators
        .iter()
        .map(|separator| {
            let len = separator.len();
            let separator_match = ndb_ascii_prefix_at_offset_condition(separator, separator_var);
            format!(
                "({separator_var} + {len} <= {size_limit} and {separator_match} and for any {prefix_var} in (0..{separator_var}) : ({prefix_clauses}))"
            )
        })
        .collect::<Vec<_>>()
        .join(" or ");

    format!("for any {separator_var} in (0..{window_end}) : ({separator_clauses})")
}

fn ndb_ascii_prefix_at_offset_condition(prefix: &str, offset_expr: &str) -> String {
    let mut parts = Vec::new();

    for (idx, b) in prefix.bytes().enumerate() {
        let target = format!("uint8(({offset_expr}) + {idx})");
        if b.is_ascii_alphabetic() {
            let upper = b.to_ascii_uppercase();
            let lower = b.to_ascii_lowercase();
            parts.push(format!(
                "({target} == 0x{upper:02X} or {target} == 0x{lower:02X})"
            ));
        } else {
            parts.push(format!("{target} == 0x{b:02X}"));
        }
    }

    join_condition(parts, "and")
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
        if start > end {
            notes.push(format!(
                "ndb absolute offset range with descending bounds {offset} is unsupported for strict lowering"
            ));
            return None;
        }
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
    }

    if let Some((start, end)) = parse_signed_range_pair(value) {
        if start >= 0 && end >= 0 {
            if start <= end {
                return Some(format!("[{start}-{end}]"));
            }
            notes.push(format!(
                "ndb range jump with descending bounds {{{value}}} is unsupported for strict lowering"
            ));
            return None;
        }

        notes.push(format!(
            "ndb signed range jump {{{value}}} is unsupported for strict lowering"
        ));
        return None;
    }

    notes.push(format!("ndb jump token {{{value}}} is unsupported"));
    None
}

fn parse_signed_range_pair(value: &str) -> Option<(i64, i64)> {
    let bytes = value.as_bytes();
    let mut sep = None;

    for idx in 1..bytes.len() {
        if bytes[idx] == b'-' && bytes[idx - 1].is_ascii_digit() {
            sep = Some(idx);
            break;
        }
    }

    let sep = sep?;
    let lhs = value[..sep].trim();
    let rhs = value[sep + 1..].trim();
    if lhs.is_empty() || rhs.is_empty() {
        return None;
    }

    let start = lhs.parse::<i64>().ok()?;
    let end = rhs.parse::<i64>().ok()?;
    Some((start, end))
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
    Some((start, end))
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
    let base_condition = lower_condition(&value.expression, &id_map, &mut notes);

    let mut imports = Vec::new();
    let mut condition_parts = vec![base_condition.clone()];
    condition_parts.extend(lower_target_description_conditions(
        &value.target_description,
        &mut imports,
        &mut notes,
    ));

    let condition = join_condition(condition_parts, "and");
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
        imports,
    })
}

fn lower_target_description_conditions(
    target: &ir::TargetDescription,
    imports: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Vec<String> {
    let mut out = Vec::new();

    if let Some((min, max)) = target.file_size {
        out.push(range_condition("filesize", min, max));
    }

    if let Some((min, max)) = target.entry_point {
        push_import(imports, "pe");
        out.push(range_condition("pe.entry_point", min, max));
    }

    if let Some((min, max)) = target.number_of_sections {
        push_import(imports, "pe");
        out.push(range_condition("pe.number_of_sections", min, max));
    }

    if let Some(container) = target.container.as_deref() {
        notes.push(format!(
            "target description Container={container} is not observable in standalone YARA scans; constrained to false for safety"
        ));
        out.push("false".to_string());
    }

    if let Some(intermediates) = target.intermediates.as_deref() {
        notes.push(format!(
            "target description Intermediates={intermediates} is not observable in standalone YARA scans; constrained to false for safety"
        ));
        out.push("false".to_string());
    }

    out
}

fn push_import(imports: &mut Vec<String>, module: &str) {
    if !imports.iter().any(|v| v == module) {
        imports.push(module.to_string());
    }
}

fn range_condition(name: &str, min: u64, max: u64) -> String {
    if min == max {
        return format!("{name} == {min}");
    }
    format!("({name} >= {min} and {name} <= {max})")
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
                let mut hex_nocase = false;
                let mut ignored = Vec::new();
                for modifier in &subsig.modifiers {
                    match modifier {
                        ir::SubsignatureModifier::CaseInsensitive => hex_nocase = true,
                        other => ignored.push(match other {
                            ir::SubsignatureModifier::Wide => "w".to_string(),
                            ir::SubsignatureModifier::Fullword => "f".to_string(),
                            ir::SubsignatureModifier::Ascii => "a".to_string(),
                            ir::SubsignatureModifier::Unknown(c) => c.to_string(),
                            ir::SubsignatureModifier::CaseInsensitive => unreachable!(),
                        }),
                    }
                }

                if !ignored.is_empty() {
                    notes.push(format!(
                        "subsig[{idx}] ignored non-nocase modifiers on hex: {}",
                        ignored.join("")
                    ));
                }

                let line = format!(
                    "{id} = {{ {} }}",
                    format_hex_bytes_with_ascii_nocase(hex, hex_nocase)
                );
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
                RawSubsigLowering::StringExpr { line, expr } => {
                    strings.push(YaraString::Raw(line));
                    id_map.push(Some(expr));
                }
                RawSubsigLowering::Alias(alias) => {
                    id_map.push(Some(alias));
                }
                RawSubsigLowering::Expr(expr) => {
                    id_map.push(Some(expr));
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
        ir::LogicalExpression::MultiGt(inner, count, distinct) => {
            if let Some(single) = lower_single_string_ref(inner, id_map, notes) {
                if *distinct > 1 {
                    notes.push(format!(
                        "multi-gt distinct threshold {distinct} ignored for single-subsig expression"
                    ));
                }
                return format!("#{single} > {count}");
            }

            if let Some(set) = lower_count_set(inner, id_map, notes) {
                let distinct_needed = *distinct;
                let count_needed = count.saturating_add(1);
                let set_expr = set.join(", ");
                notes.push(
                    "multi-gt on grouped expression approximated with distinct-match counts"
                        .to_string(),
                );
                format!("({distinct_needed} of ({set_expr})) and ({count_needed} of ({set_expr}))")
            } else {
                "false".to_string()
            }
        }
        ir::LogicalExpression::MultiLt(inner, count, distinct) => {
            if *count == 0 {
                notes.push("expression '<0,y' is impossible; lowered to false".to_string());
                return "false".to_string();
            }

            if let Some(single) = lower_single_string_ref(inner, id_map, notes) {
                if *distinct > 1 {
                    notes.push(format!(
                        "multi-lt distinct threshold {distinct} ignored for single-subsig expression"
                    ));
                }
                return format!("#{single} < {count}");
            }

            if *distinct >= *count {
                notes.push(format!(
                    "multi-lt distinct threshold {distinct} is incompatible with <{count}; lowered to false"
                ));
                return "false".to_string();
            }

            if let Some(set) = lower_count_set(inner, id_map, notes) {
                let set_expr = set.join(", ");
                notes.push(
                    "multi-lt on grouped expression approximated with distinct-match counts"
                        .to_string(),
                );
                format!("({distinct} of ({set_expr})) and not ({count} of ({set_expr}))")
            } else {
                "false".to_string()
            }
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

fn lower_single_string_ref(
    expr: &ir::LogicalExpression,
    id_map: &[Option<String>],
    notes: &mut Vec<String>,
) -> Option<String> {
    let ir::LogicalExpression::SubExpression(idx) = expr else {
        return None;
    };

    let id = id_for(*idx, id_map, notes);
    if id == "false" {
        return None;
    }
    if !is_yara_string_identifier(&id) {
        notes.push(format!(
            "single-count comparator references non-string subsig index {}; lowered to false",
            idx
        ));
        return None;
    }

    Some(id.trim_start_matches('$').to_string())
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
            if id == "false" {
                return true;
            }

            if !is_yara_string_identifier(&id) {
                notes.push(format!(
                    "count expression references non-string subsig index {}; lowered to false",
                    idx
                ));
                return false;
            }

            if !out.contains(&id) {
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

fn format_hex_bytes_with_ascii_nocase(input: &str, nocase: bool) -> String {
    if !nocase {
        return format_hex_bytes(input);
    }

    let mut out = Vec::new();
    for chunk in input.as_bytes().chunks(2) {
        let token = String::from_utf8_lossy(chunk).to_string();
        let Ok(byte) = u8::from_str_radix(&token, 16) else {
            out.push(token.to_uppercase());
            continue;
        };

        let upper = byte.to_ascii_uppercase();
        let lower = byte.to_ascii_lowercase();

        if byte.is_ascii_alphabetic() && upper != lower {
            out.push(format!("({:02X}|{:02X})", upper, lower));
        } else {
            out.push(format!("{:02X}", byte));
        }
    }

    out.join(" ")
}

#[allow(dead_code)]
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
    StringExpr { line: String, expr: String },
    Alias(String),
    Expr(String),
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

    if let Some(byte_cmp) = parse_byte_comparison(raw) {
        if let Some(lowered) = lower_byte_comparison_condition(idx, &byte_cmp, known_ids, notes) {
            return RawSubsigLowering::Expr(lowered);
        }

        if let Some(Some(alias)) = known_ids.get(byte_cmp.trigger_idx) {
            notes.push(format!(
                "subsig[{idx}] byte_comparison fell back to trigger alias subsig[{}]",
                byte_cmp.trigger_idx
            ));
            return RawSubsigLowering::Alias(alias.clone());
        }

        notes.push(format!(
            "subsig[{idx}] byte_comparison trigger {} unresolved; lowered to false",
            byte_cmp.trigger_idx
        ));
        return RawSubsigLowering::Skip;
    }

    if let Some(macro_sig) = parse_macro_subsignature(raw) {
        let lowered = lower_macro_subsignature_condition(idx, &macro_sig, known_ids, notes);
        return RawSubsigLowering::Expr(lowered);
    }

    if looks_like_macro_subsignature(raw) {
        notes.push(format!(
            "subsig[{idx}] macro subsignature format unsupported/invalid (expected `${{min-max}}group$`); lowered to false for safety"
        ));
        return RawSubsigLowering::Expr("false".to_string());
    }

    if let Some(fuzzy) = parse_fuzzy_img_subsignature(raw) {
        notes.push(format!(
            "subsig[{idx}] fuzzy_img hash '{}' is not representable in YARA; lowered to false",
            preview_for_meta(&fuzzy.hash, 16)
        ));
        if fuzzy.distance != 0 {
            notes.push(format!(
                "subsig[{idx}] fuzzy_img distance={} unsupported; lowered to false",
                fuzzy.distance
            ));
        }
        return RawSubsigLowering::Expr("false".to_string());
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
        let mut inline_flags = String::new();
        let mut anchored = false;
        let mut rolling = false;
        let mut encompass = false;
        let mut unsupported_e_flag = false;
        let mut unsupported_flags = Vec::new();

        for flag in pcre.flags.chars() {
            match flag {
                'i' => string_mods.nocase = true,
                's' | 'm' => {
                    if !inline_flags.contains(flag) {
                        inline_flags.push(flag);
                    }
                }
                'A' => anchored = true,
                'r' => rolling = true,
                'e' => encompass = true,
                'g' => notes.push(format!(
                    "subsig[{idx}] pcre flag 'g' treated as no-op (YARA already searches globally)"
                )),
                'x' => {
                    if !inline_flags.contains('x') {
                        inline_flags.push('x');
                    }
                }
                'E' => unsupported_e_flag = true,
                'U' => {
                    if !inline_flags.contains('U') {
                        inline_flags.push('U');
                    }
                }
                'a' => {
                    anchored = true;
                    notes.push(format!(
                        "subsig[{idx}] legacy pcre flag 'a' treated as anchored"
                    ));
                }
                'd' => unsupported_flags.push('d'),
                other => unsupported_flags.push(other),
            }
        }

        if unsupported_e_flag {
            notes.push(format!(
                "subsig[{idx}] pcre flag 'E' unsupported; lowered to false for safety"
            ));
            return RawSubsigLowering::Expr("false".to_string());
        }

        if !unsupported_flags.is_empty() {
            unsupported_flags.sort_unstable();
            unsupported_flags.dedup();
            let rendered = unsupported_flags
                .iter()
                .map(|ch| format!("'{}'", ch))
                .collect::<Vec<_>>()
                .join(", ");
            notes.push(format!(
                "subsig[{idx}] unsupported pcre flag(s) {rendered}; lowered to false for safety"
            ));
            return RawSubsigLowering::Expr("false".to_string());
        }

        let mut rendered_pattern = pcre.pattern.to_string();
        if anchored {
            rendered_pattern = format!("\\A(?:{})", rendered_pattern);
        }
        if !inline_flags.is_empty() {
            rendered_pattern = format!("(?{}:{})", inline_flags, rendered_pattern);
        }

        let render_mods = render_string_modifiers(&string_mods);
        let line = format!("{id} = /{}/{render_mods}", rendered_pattern);

        if let Some(expr) =
            lower_pcre_trigger_condition(idx, id, pcre.prefix, rolling, encompass, known_ids, notes)
        {
            return RawSubsigLowering::StringExpr { line, expr };
        }

        return RawSubsigLowering::String(line);
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

#[derive(Debug, Clone, Copy)]
enum ByteCmpBase {
    Hex,
    Decimal,
    Auto,
    Raw,
}

#[derive(Debug, Clone, Copy)]
enum ByteCmpEndian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
enum ByteCmpOp {
    Gt,
    Lt,
    Eq,
}

#[derive(Debug, Clone, Copy)]
struct ByteCmpOptions {
    base: Option<ByteCmpBase>,
    endian: Option<ByteCmpEndian>,
    exact: bool,
    num_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct ByteCmpClause {
    op: ByteCmpOp,
    value: u64,
    contains_hex_alpha: bool,
}

#[derive(Debug, Clone)]
struct ParsedByteComparison {
    trigger_idx: usize,
    offset: i64,
    options: ByteCmpOptions,
    comparisons: Vec<ByteCmpClause>,
}

fn parse_byte_comparison(raw: &str) -> Option<ParsedByteComparison> {
    let open = raw.find('(')?;
    if open == 0 || !raw.ends_with(')') || !raw.contains('#') {
        return None;
    }

    let trigger = &raw[..open];
    if !trigger.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let trigger_idx = trigger.parse::<usize>().ok()?;

    let inner = &raw[open + 1..raw.len() - 1];
    let mut parts = inner.split('#');
    let offset_part = parts.next()?.trim();
    let options_part = parts.next()?.trim();
    let comparisons_part = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }

    let offset = parse_byte_comparison_offset(offset_part)?;
    let options = parse_byte_comparison_options(options_part)?;
    let comparisons = parse_byte_comparison_clauses(comparisons_part)?;
    if comparisons.is_empty() {
        return None;
    }

    Some(ParsedByteComparison {
        trigger_idx,
        offset,
        options,
        comparisons,
    })
}

fn parse_byte_comparison_offset(input: &str) -> Option<i64> {
    let (sign, rest) = if let Some(rest) = input.strip_prefix(">>") {
        (1i64, rest)
    } else if let Some(rest) = input.strip_prefix("<<") {
        (-1i64, rest)
    } else {
        return None;
    };

    let value = parse_clamav_numeric(rest)? as i64;
    Some(sign * value)
}

fn parse_byte_comparison_options(input: &str) -> Option<ByteCmpOptions> {
    if input.is_empty() {
        return None;
    }

    let chars: Vec<char> = input.chars().collect();
    let mut idx = 0usize;

    let base = if idx < chars.len() {
        match chars[idx] {
            'h' => {
                idx += 1;
                Some(ByteCmpBase::Hex)
            }
            'd' => {
                idx += 1;
                Some(ByteCmpBase::Decimal)
            }
            'a' => {
                idx += 1;
                Some(ByteCmpBase::Auto)
            }
            'i' => {
                idx += 1;
                Some(ByteCmpBase::Raw)
            }
            _ => None,
        }
    } else {
        None
    };

    let endian = if idx < chars.len() {
        match chars[idx] {
            'l' => {
                idx += 1;
                Some(ByteCmpEndian::Little)
            }
            'b' => {
                idx += 1;
                Some(ByteCmpEndian::Big)
            }
            _ => None,
        }
    } else {
        None
    };

    let exact = if idx < chars.len() && chars[idx] == 'e' {
        idx += 1;
        true
    } else {
        false
    };

    if idx >= chars.len() {
        return None;
    }

    let num_bytes = parse_clamav_numeric(&input[idx..])?;

    Some(ByteCmpOptions {
        base,
        endian,
        exact,
        num_bytes,
    })
}

fn parse_byte_comparison_clauses(input: &str) -> Option<Vec<ByteCmpClause>> {
    let mut out = Vec::new();

    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }

        let (op, value_str) = match token.as_bytes().first().copied() {
            Some(b'>') => (ByteCmpOp::Gt, &token[1..]),
            Some(b'<') => (ByteCmpOp::Lt, &token[1..]),
            Some(b'=') => (ByteCmpOp::Eq, &token[1..]),
            _ => return None,
        };

        let value_str = value_str.trim();
        let value = parse_clamav_numeric(value_str)?;
        let contains_hex_alpha = value_str
            .bytes()
            .any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'));
        out.push(ByteCmpClause {
            op,
            value,
            contains_hex_alpha,
        });
    }

    Some(out)
}

fn parse_clamav_numeric(input: &str) -> Option<u64> {
    if input.is_empty() {
        return None;
    }

    if input.chars().all(|c| c.is_ascii_digit()) {
        return input.parse::<u64>().ok();
    }

    if input.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(input, 16).ok();
    }

    None
}

fn byte_cmp_clauses_unsatisfiable(clauses: &[ByteCmpClause]) -> bool {
    if clauses.is_empty() {
        return true;
    }

    let mut eq_value: Option<u64> = None;
    let mut lower_exclusive: Option<u64> = None;
    let mut upper_exclusive: Option<u64> = None;

    for clause in clauses {
        match clause.op {
            ByteCmpOp::Eq => {
                if let Some(existing) = eq_value {
                    if existing != clause.value {
                        return true;
                    }
                } else {
                    eq_value = Some(clause.value);
                }
            }
            ByteCmpOp::Gt => {
                lower_exclusive = Some(match lower_exclusive {
                    Some(v) => v.max(clause.value),
                    None => clause.value,
                });
            }
            ByteCmpOp::Lt => {
                upper_exclusive = Some(match upper_exclusive {
                    Some(v) => v.min(clause.value),
                    None => clause.value,
                });
            }
        }
    }

    if let Some(eq) = eq_value {
        if let Some(lower) = lower_exclusive {
            if eq <= lower {
                return true;
            }
        }
        if let Some(upper) = upper_exclusive {
            if eq >= upper {
                return true;
            }
        }
        return false;
    }

    if let (Some(lower), Some(upper)) = (lower_exclusive, upper_exclusive) {
        if lower >= upper.saturating_sub(1) {
            return true;
        }
    }

    false
}

fn lower_byte_comparison_condition(
    idx: usize,
    byte_cmp: &ParsedByteComparison,
    known_ids: &[Option<String>],
    notes: &mut Vec<String>,
) -> Option<String> {
    if byte_cmp_clauses_unsatisfiable(&byte_cmp.comparisons) {
        notes.push(format!(
            "subsig[{idx}] byte_comparison clauses are contradictory; lowered to false for safety"
        ));
        return Some("false".to_string());
    }

    let Some(trigger_id) = known_ids
        .get(byte_cmp.trigger_idx)
        .and_then(|v| v.as_ref())
        .cloned()
    else {
        notes.push(format!(
            "subsig[{idx}] byte_comparison trigger {} unresolved; lowered to false for safety",
            byte_cmp.trigger_idx
        ));
        return Some("false".to_string());
    };

    if !is_yara_string_identifier(&trigger_id) {
        notes.push(format!(
            "subsig[{idx}] byte_comparison trigger {} is not a direct string id; lowered to false for safety",
            byte_cmp.trigger_idx
        ));
        return Some("false".to_string());
    }

    let base = byte_cmp.options.base.unwrap_or(ByteCmpBase::Auto);
    let num_bytes = byte_cmp.options.num_bytes;

    let core = trigger_id.strip_prefix('$').unwrap_or(&trigger_id);

    let start_expr = if byte_cmp.offset >= 0 {
        format!("@{core}[j] + {}", byte_cmp.offset)
    } else {
        format!("@{core}[j] - {}", byte_cmp.offset.unsigned_abs())
    };

    let mut base_guards = Vec::new();
    if byte_cmp.offset < 0 {
        base_guards.push(format!("@{core}[j] >= {}", byte_cmp.offset.unsigned_abs()));
    }

    if !matches!(base, ByteCmpBase::Raw) {
        return lower_textual_byte_comparison_condition(
            idx,
            core,
            &start_expr,
            base,
            byte_cmp,
            &base_guards,
            notes,
        );
    }

    let endian = byte_cmp.options.endian.unwrap_or(ByteCmpEndian::Big);
    let num_bytes = match usize::try_from(num_bytes) {
        Ok(v) if (1..=8).contains(&v) => v,
        _ => {
            notes.push(format!(
                "subsig[{idx}] byte_comparison raw size {} unsupported (use 1..8); lowered to false for safety",
                byte_cmp.options.num_bytes
            ));
            return Some("false".to_string());
        }
    };

    let max_raw_value = if num_bytes == 8 {
        u64::MAX
    } else {
        ((1u128 << (num_bytes * 8)) - 1) as u64
    };

    for cmp in &byte_cmp.comparisons {
        if cmp.value > max_raw_value {
            notes.push(format!(
                "subsig[{idx}] byte_comparison raw threshold {} exceeds {}-byte range; lowered to false for safety",
                cmp.value, num_bytes
            ));
            return Some("false".to_string());
        }
    }

    let mut guards = base_guards;
    guards.push(format!("({start_expr}) + {num_bytes} <= filesize"));

    let value_expr = match (endian, num_bytes) {
        (ByteCmpEndian::Little, 1) => format!("uint8({start_expr})"),
        (ByteCmpEndian::Little, 2) => format!("uint16({start_expr})"),
        (ByteCmpEndian::Little, 4) => format!("uint32({start_expr})"),
        (ByteCmpEndian::Little, 8) => format!("uint64({start_expr})"),
        (ByteCmpEndian::Big, 1) => format!("uint8({start_expr})"),
        (ByteCmpEndian::Big, 2) => format!("uint16be({start_expr})"),
        (ByteCmpEndian::Big, 4) => format!("uint32be({start_expr})"),
        (ByteCmpEndian::Big, 8) => format!("uint64be({start_expr})"),
        _ => build_raw_byte_comparison_value_expr(&start_expr, num_bytes, endian),
    };
    let mut cmp_parts = Vec::new();
    for cmp in &byte_cmp.comparisons {
        let expr = match cmp.op {
            ByteCmpOp::Gt => format!("{value_expr} > {}", cmp.value),
            ByteCmpOp::Lt => format!("{value_expr} < {}", cmp.value),
            ByteCmpOp::Eq => format!("{value_expr} == {}", cmp.value),
        };
        cmp_parts.push(expr);
    }

    let mut clause_parts = guards;
    clause_parts.extend(cmp_parts);

    Some(format!(
        "for any j in (1..#{core}) : ({})",
        clause_parts.join(" and ")
    ))
}

fn build_raw_byte_comparison_value_expr(
    start_expr: &str,
    num_bytes: usize,
    endian: ByteCmpEndian,
) -> String {
    if num_bytes == 1 {
        return format!("uint8({start_expr})");
    }

    let mut terms = Vec::with_capacity(num_bytes);

    for idx in 0..num_bytes {
        let (offset, shift_bits) = match endian {
            ByteCmpEndian::Big => (idx, 8 * (num_bytes - 1 - idx)),
            ByteCmpEndian::Little => (idx, 8 * idx),
        };

        let byte_expr = format!("uint8(({start_expr}) + {offset})");
        let term = if shift_bits == 0 {
            byte_expr
        } else {
            format!("(({byte_expr}) << {shift_bits})")
        };
        terms.push(term);
    }

    format!("({})", terms.join(" | "))
}

fn lower_textual_byte_comparison_condition(
    idx: usize,
    core: &str,
    start_expr: &str,
    base: ByteCmpBase,
    byte_cmp: &ParsedByteComparison,
    base_guards: &[String],
    notes: &mut Vec<String>,
) -> Option<String> {
    if matches!(byte_cmp.options.endian, Some(ByteCmpEndian::Little)) {
        notes.push(format!(
            "subsig[{idx}] byte_comparison non-raw little-endian unsupported; lowered to false for safety"
        ));
        return Some("false".to_string());
    }

    if !byte_cmp.options.exact {
        notes.push(format!(
            "subsig[{idx}] byte_comparison non-raw non-exact unsupported; lowered to false for safety"
        ));
        return Some("false".to_string());
    }

    if matches!(base, ByteCmpBase::Decimal)
        && byte_cmp
            .comparisons
            .iter()
            .any(|cmp| cmp.contains_hex_alpha)
    {
        notes.push(format!(
            "subsig[{idx}] byte_comparison decimal base cannot use hex-alpha threshold token; lowered to false for safety"
        ));
        return Some("false".to_string());
    }

    let width = match usize::try_from(byte_cmp.options.num_bytes) {
        Ok(v) if v > 0 && v <= 64 => v,
        _ => {
            notes.push(format!(
                "subsig[{idx}] byte_comparison non-raw width {} unsupported; lowered to false for safety",
                byte_cmp.options.num_bytes
            ));
            return Some("false".to_string());
        }
    };

    let mut guards = base_guards.to_vec();
    guards.push(format!("({start_expr}) + {width} <= filesize"));

    let mut cmp_parts = Vec::new();
    for cmp in &byte_cmp.comparisons {
        let threshold_specs = build_textual_threshold_specs(base, width, cmp.value);
        if threshold_specs.is_empty() {
            notes.push(format!(
                "subsig[{idx}] byte_comparison non-raw cannot represent value {} in width {}; lowered to false for safety",
                cmp.value, width
            ));
            return Some("false".to_string());
        }

        let mut exprs = Vec::new();
        for spec in &threshold_specs {
            let expr = build_textual_clause_condition(start_expr, spec, cmp.op);
            if !exprs.contains(&expr) {
                exprs.push(expr);
            }
        }

        let clause = if exprs.len() == 1 {
            exprs[0].clone()
        } else {
            join_condition(exprs, "or")
        };

        cmp_parts.push(clause);
    }

    let mut clause_parts = guards;
    clause_parts.extend(cmp_parts);

    Some(format!(
        "for any j in (1..#{core}) : ({})",
        clause_parts.join(" and ")
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextualRadix {
    Decimal,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TextualThresholdSpec {
    radix: TextualRadix,
    digits: Vec<u8>,
}

fn build_textual_threshold_specs(
    base: ByteCmpBase,
    width: usize,
    value: u64,
) -> Vec<TextualThresholdSpec> {
    let mut out = Vec::new();

    let push_unique = |items: &mut Vec<TextualThresholdSpec>,
                       candidate: Option<TextualThresholdSpec>| {
        if let Some(candidate) = candidate {
            if !items.contains(&candidate) {
                items.push(candidate);
            }
        }
    };

    match base {
        ByteCmpBase::Hex => push_unique(&mut out, build_hex_textual_threshold(width, value)),
        ByteCmpBase::Decimal => {
            push_unique(&mut out, build_decimal_textual_threshold(width, value))
        }
        ByteCmpBase::Auto => {
            push_unique(&mut out, build_decimal_textual_threshold(width, value));
            push_unique(&mut out, build_hex_textual_threshold(width, value));
        }
        ByteCmpBase::Raw => {}
    }

    out
}

fn build_decimal_textual_threshold(width: usize, value: u64) -> Option<TextualThresholdSpec> {
    let raw = value.to_string();
    if raw.len() > width {
        return None;
    }

    let text = format!("{value:0width$}");
    let mut digits = Vec::with_capacity(width);
    for b in text.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        digits.push(b - b'0');
    }

    Some(TextualThresholdSpec {
        radix: TextualRadix::Decimal,
        digits,
    })
}

fn build_hex_textual_threshold(width: usize, value: u64) -> Option<TextualThresholdSpec> {
    let raw = format!("{value:X}");
    if raw.len() > width {
        return None;
    }

    let text = format!("{raw:0>width$}");
    let mut digits = Vec::with_capacity(width);
    for b in text.bytes() {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'F' => 10 + (b - b'A'),
            _ => return None,
        };
        digits.push(digit);
    }

    Some(TextualThresholdSpec {
        radix: TextualRadix::Hex,
        digits,
    })
}

fn build_textual_clause_condition(
    start_expr: &str,
    threshold: &TextualThresholdSpec,
    op: ByteCmpOp,
) -> String {
    let all_valid = build_textual_all_valid_condition(start_expr, threshold);

    let cmp_expr = match op {
        ByteCmpOp::Eq => {
            let mut parts = Vec::new();
            for (pos, digit) in threshold.digits.iter().enumerate() {
                parts.push(build_textual_digit_eq_condition(
                    start_expr,
                    pos,
                    threshold.radix,
                    *digit,
                ));
            }
            join_condition(parts, "and")
        }
        ByteCmpOp::Gt | ByteCmpOp::Lt => {
            let mut branches = Vec::new();
            for pos in 0..threshold.digits.len() {
                let mut parts = Vec::new();
                for prev in 0..pos {
                    parts.push(build_textual_digit_eq_condition(
                        start_expr,
                        prev,
                        threshold.radix,
                        threshold.digits[prev],
                    ));
                }

                let boundary = match op {
                    ByteCmpOp::Gt => build_textual_digit_gt_condition(
                        start_expr,
                        pos,
                        threshold.radix,
                        threshold.digits[pos],
                    ),
                    ByteCmpOp::Lt => build_textual_digit_lt_condition(
                        start_expr,
                        pos,
                        threshold.radix,
                        threshold.digits[pos],
                    ),
                    ByteCmpOp::Eq => unreachable!(),
                };

                let Some(boundary) = boundary else {
                    continue;
                };

                parts.push(boundary);
                branches.push(join_condition(parts, "and"));
            }

            if branches.is_empty() {
                "false".to_string()
            } else {
                join_condition(branches, "or")
            }
        }
    };

    format!("({all_valid} and {cmp_expr})")
}

fn build_textual_all_valid_condition(start_expr: &str, threshold: &TextualThresholdSpec) -> String {
    let mut parts = Vec::new();
    for pos in 0..threshold.digits.len() {
        parts.push(build_textual_digit_valid_condition(
            start_expr,
            pos,
            threshold.radix,
        ));
    }
    join_condition(parts, "and")
}

fn build_textual_digit_valid_condition(
    start_expr: &str,
    pos: usize,
    radix: TextualRadix,
) -> String {
    let lhs = format!("uint8(({start_expr}) + {pos})");
    match radix {
        TextualRadix::Decimal => format!("({lhs} >= 0x30 and {lhs} <= 0x39)"),
        TextualRadix::Hex => format!(
            "(({lhs} >= 0x30 and {lhs} <= 0x39) or ({lhs} >= 0x41 and {lhs} <= 0x46) or ({lhs} >= 0x61 and {lhs} <= 0x66))"
        ),
    }
}

fn build_textual_digit_eq_condition(
    start_expr: &str,
    pos: usize,
    radix: TextualRadix,
    digit: u8,
) -> String {
    let lhs = format!("uint8(({start_expr}) + {pos})");

    match radix {
        TextualRadix::Decimal => format!("{lhs} == 0x{:02X}", b'0' + digit),
        TextualRadix::Hex => {
            if digit < 10 {
                format!("{lhs} == 0x{:02X}", b'0' + digit)
            } else {
                let upper = b'A' + (digit - 10);
                let lower = b'a' + (digit - 10);
                format!("({lhs} == 0x{upper:02X} or {lhs} == 0x{lower:02X})")
            }
        }
    }
}

fn build_textual_digit_gt_condition(
    start_expr: &str,
    pos: usize,
    radix: TextualRadix,
    digit: u8,
) -> Option<String> {
    let lhs = format!("uint8(({start_expr}) + {pos})");

    match radix {
        TextualRadix::Decimal => {
            if digit >= 9 {
                None
            } else {
                let min = b'0' + digit + 1;
                Some(format!("({lhs} >= 0x{min:02X} and {lhs} <= 0x39)"))
            }
        }
        TextualRadix::Hex => {
            if digit >= 15 {
                return None;
            }

            let mut alts = Vec::new();
            if digit < 9 {
                let min = b'0' + digit + 1;
                alts.push(format!("({lhs} >= 0x{min:02X} and {lhs} <= 0x39)"));
                alts.push(format!("({lhs} >= 0x41 and {lhs} <= 0x46)"));
                alts.push(format!("({lhs} >= 0x61 and {lhs} <= 0x66)"));
            } else if digit == 9 {
                alts.push(format!("({lhs} >= 0x41 and {lhs} <= 0x46)"));
                alts.push(format!("({lhs} >= 0x61 and {lhs} <= 0x66)"));
            } else {
                for next in (digit + 1)..=15 {
                    alts.push(build_textual_digit_eq_condition(
                        start_expr,
                        pos,
                        TextualRadix::Hex,
                        next,
                    ));
                }
            }

            if alts.is_empty() {
                None
            } else {
                Some(join_condition(alts, "or"))
            }
        }
    }
}

fn build_textual_digit_lt_condition(
    start_expr: &str,
    pos: usize,
    radix: TextualRadix,
    digit: u8,
) -> Option<String> {
    let lhs = format!("uint8(({start_expr}) + {pos})");

    match radix {
        TextualRadix::Decimal => {
            if digit == 0 {
                None
            } else {
                let max = b'0' + digit - 1;
                Some(format!("({lhs} >= 0x30 and {lhs} <= 0x{max:02X})"))
            }
        }
        TextualRadix::Hex => {
            if digit == 0 {
                return None;
            }

            let mut alts = Vec::new();
            if digit <= 10 {
                let max = b'0' + (digit - 1);
                alts.push(format!("({lhs} >= 0x30 and {lhs} <= 0x{max:02X})"));
            } else {
                alts.push(format!("({lhs} >= 0x30 and {lhs} <= 0x39)"));
                for prev in 10..digit {
                    alts.push(build_textual_digit_eq_condition(
                        start_expr,
                        pos,
                        TextualRadix::Hex,
                        prev,
                    ));
                }
            }

            if alts.is_empty() {
                None
            } else {
                Some(join_condition(alts, "or"))
            }
        }
    }
}

fn is_yara_string_identifier(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('$') else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, Copy)]
struct ParsedMacroSubsignature {
    min: u64,
    max: u64,
    group_id: u32,
}

fn looks_like_macro_subsignature(raw: &str) -> bool {
    raw.starts_with("${") && raw.ends_with('$')
}

fn parse_macro_subsignature(raw: &str) -> Option<ParsedMacroSubsignature> {
    if !looks_like_macro_subsignature(raw) {
        return None;
    }

    let close = raw.find('}')?;
    if close + 2 > raw.len() {
        return None;
    }

    let range = &raw[2..close];
    let (min, max) = parse_macro_range(range)?;

    let group_part = &raw[close + 1..raw.len() - 1];
    if group_part.is_empty() || !group_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let group_id = group_part.parse::<u32>().ok()?;

    Some(ParsedMacroSubsignature { min, max, group_id })
}

fn parse_macro_range(range: &str) -> Option<(u64, u64)> {
    let (lhs, rhs) = range.split_once('-')?;
    let min = lhs.trim().parse::<u64>().ok()?;
    let max = rhs.trim().parse::<u64>().ok()?;
    Some((min, max))
}

fn lower_macro_subsignature_condition(
    idx: usize,
    macro_sig: &ParsedMacroSubsignature,
    _known_ids: &[Option<String>],
    notes: &mut Vec<String>,
) -> String {
    if macro_sig.group_id >= 32 {
        notes.push(format!(
            "subsig[{idx}] macro group {} out of range (ClamAV supports 0..31); lowered to false for safety",
            macro_sig.group_id
        ));
        return "false".to_string();
    }

    if macro_sig.min > macro_sig.max {
        notes.push(format!(
            "subsig[{idx}] macro descending range {}-{} unsupported; lowered to false for safety",
            macro_sig.min, macro_sig.max
        ));
        return "false".to_string();
    }

    if idx == 0 {
        notes.push(format!(
            "subsig[{idx}] macro cannot be first subsig (no preceding anchor subsig); lowered to false for safety"
        ));
    }

    notes.push(format!(
        "subsig[{idx}] macro-group `${}$` semantics depend on CLI_OFF_MACRO anchors and matcher-ac macro_lastmatch state; lowered to false for safety",
        macro_sig.group_id
    ));

    "false".to_string()
}

#[derive(Debug, Clone)]
struct ParsedFuzzyImg {
    hash: String,
    distance: u64,
}

fn parse_fuzzy_img_subsignature(raw: &str) -> Option<ParsedFuzzyImg> {
    let rest = raw.strip_prefix("fuzzy_img#")?;
    let (hash, distance) = match rest.split_once('#') {
        Some((hash, dist)) => (hash, dist),
        None => (rest, "0"),
    };

    if hash.is_empty() || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let distance = distance.parse::<u64>().ok()?;

    Some(ParsedFuzzyImg {
        hash: hash.to_string(),
        distance,
    })
}

#[derive(Debug, Clone)]
enum PcreOffsetSpec {
    Exact(u64),
    Range { start: u64, maxshift: u64 },
    MacroGroup(u32),
    Unsupported(String),
}

#[derive(Debug, Clone)]
struct ParsedPcrePrefix<'a> {
    trigger: &'a str,
    offset: Option<PcreOffsetSpec>,
}

struct ParsedPcre<'a> {
    pattern: &'a str,
    flags: &'a str,
    prefix: Option<&'a str>,
}

fn lower_pcre_trigger_condition(
    idx: usize,
    id: &str,
    prefix: Option<&str>,
    rolling: bool,
    encompass: bool,
    known_ids: &[Option<String>],
    notes: &mut Vec<String>,
) -> Option<String> {
    let prefix = prefix?.trim();
    if prefix.is_empty() {
        return None;
    }

    let parsed_prefix = match parse_pcre_trigger_prefix(prefix) {
        Ok(v) => v,
        Err(reason) => {
            notes.push(format!(
                "subsig[{idx}] pcre trigger prefix parse failed ({reason}); lowered to false for safety"
            ));
            return Some("false".to_string());
        }
    };

    let trigger_ir = match parse_expression_to_ir(parsed_prefix.trigger) {
        Ok(v) => v,
        Err(_) => {
            notes.push(format!(
                "subsig[{idx}] pcre trigger expression parse failed; lowered to false for safety"
            ));
            return Some("false".to_string());
        }
    };

    let trigger_expr = lower_condition(&trigger_ir, known_ids, notes);
    if trigger_expr == "false" {
        notes.push(format!(
            "subsig[{idx}] pcre trigger expression resolved to false; trigger constraint ignored"
        ));
        return None;
    }

    let mut parts = vec![id.to_string(), format!("({trigger_expr})")];

    if let Some(offset_expr) =
        lower_pcre_offset_condition(idx, id, parsed_prefix.offset, rolling, encompass, notes)
    {
        parts.push(format!("({offset_expr})"));
    }

    Some(join_condition(parts, "and"))
}

fn parse_pcre_trigger_prefix(prefix: &str) -> Result<ParsedPcrePrefix<'_>, String> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Err("empty trigger prefix".to_string());
    }

    if let Some((lhs, rhs)) = prefix.split_once(':') {
        let trigger = rhs.trim();
        if trigger.is_empty() {
            return Err("missing trigger expression after ':'".to_string());
        }

        return Ok(ParsedPcrePrefix {
            trigger,
            offset: Some(parse_pcre_offset_spec(lhs.trim())),
        });
    }

    Ok(ParsedPcrePrefix {
        trigger: prefix,
        offset: None,
    })
}

fn parse_pcre_macro_group_offset(input: &str) -> Option<u32> {
    let inner = input.strip_prefix('$')?.strip_suffix('$')?;
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    inner.parse::<u32>().ok()
}

fn parse_pcre_offset_spec(input: &str) -> PcreOffsetSpec {
    let input = input.trim();

    if let Some(group_id) = parse_pcre_macro_group_offset(input) {
        return PcreOffsetSpec::MacroGroup(group_id);
    }

    if let Some((start, maxshift)) = input.split_once(',') {
        if let (Some(start), Some(maxshift)) = (
            parse_clamav_numeric(start.trim()),
            parse_clamav_numeric(maxshift.trim()),
        ) {
            return PcreOffsetSpec::Range { start, maxshift };
        }

        return PcreOffsetSpec::Unsupported(input.to_string());
    }

    if let Some(value) = parse_clamav_numeric(input) {
        return PcreOffsetSpec::Exact(value);
    }

    PcreOffsetSpec::Unsupported(input.to_string())
}

fn lower_pcre_offset_condition(
    idx: usize,
    id: &str,
    offset: Option<PcreOffsetSpec>,
    rolling: bool,
    encompass: bool,
    notes: &mut Vec<String>,
) -> Option<String> {
    let core = id.strip_prefix('$').unwrap_or(id);

    let Some(offset) = offset else {
        if rolling {
            notes.push(format!(
                "subsig[{idx}] pcre flag 'r' ignored: no offset prefix"
            ));
        }
        if encompass {
            notes.push(format!(
                "subsig[{idx}] pcre flag 'e' ignored: no maxshift in offset prefix"
            ));
        }
        return None;
    };

    match offset {
        PcreOffsetSpec::Exact(start) => {
            if encompass {
                notes.push(format!(
                    "subsig[{idx}] pcre flag 'e' ignored on exact offset"
                ));
            }

            if rolling {
                Some(format!(
                    "for any j in (1..#{core}) : (@{core}[j] >= {start})"
                ))
            } else {
                Some(format!(
                    "for any j in (1..#{core}) : (@{core}[j] == {start})"
                ))
            }
        }
        PcreOffsetSpec::Range { start, maxshift } => {
            if rolling {
                notes.push(format!(
                    "subsig[{idx}] pcre flag 'r' ignored when maxshift is present"
                ));
            }

            if encompass {
                Some(format!(
                    "for any j in (1..#{core}) : (@{core}[j] >= {start} and @{core}[j] <= {})",
                    start.saturating_add(maxshift)
                ))
            } else {
                notes.push(format!(
                    "subsig[{idx}] pcre maxshift present without 'e'; lowered to false for safety"
                ));
                Some("false".to_string())
            }
        }
        PcreOffsetSpec::MacroGroup(group_id) => {
            if group_id >= 32 {
                notes.push(format!(
                    "subsig[{idx}] pcre macro-group offset `${group_id}$` out of range (ClamAV supports 0..31); lowered to false for safety"
                ));
            } else {
                notes.push(format!(
                    "subsig[{idx}] pcre offset `${group_id}$` depends on CLI_OFF_MACRO runtime state; lowered to false for safety"
                ));
            }
            Some("false".to_string())
        }
        PcreOffsetSpec::Unsupported(raw) => {
            notes.push(format!(
                "subsig[{idx}] pcre offset prefix '{raw}' unsupported (ClamAV supports richer cli_caloff forms); lowered to false for safety"
            ));
            Some("false".to_string())
        }
    }
}

fn parse_pcre_like(raw: &str) -> Option<ParsedPcre<'_>> {
    let start = raw.find('/')?;
    let prefix = raw[..start].trim();

    let tail = &raw[start + 1..];
    let end_rel = tail.rfind('/')?;
    let end = start + 1 + end_rel;

    let pattern = &raw[start + 1..end];
    if pattern.is_empty() {
        return None;
    }

    let flags = raw[end + 1..].trim();
    if !flags.is_empty() && !flags.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    Some(ParsedPcre {
        pattern,
        flags,
        prefix: if prefix.is_empty() {
            None
        } else {
            Some(prefix)
        },
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
