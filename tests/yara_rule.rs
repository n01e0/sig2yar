use sig2yar::parser::{logical::LogicalSignature, ndb::NdbSignature};
use sig2yar::yara::{YaraMeta, YaraRule, YaraString};

#[test]
fn build_yara_rule_from_logical_signature() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.name, "Foo_Bar_1");
    assert!(rule.meta.len() >= 2);

    match &rule.meta[0] {
        YaraMeta::Entry { key, value } => {
            assert_eq!(key, "original_ident");
            assert_eq!(value, "Foo.Bar-1");
        }
        _ => panic!("expected meta entry for original_ident"),
    }

    let mut has_target = false;
    for entry in &rule.meta {
        if let YaraMeta::Entry { key, value } = entry {
            if key == "clamav_target_description" {
                assert!(value.contains("target"));
                has_target = true;
            }
        }
    }
    assert!(has_target);

    assert_eq!(rule.strings.len(), 1);
    assert_eq!(rule.condition, "$s0");
}

#[test]
fn logical_display_matches_yara_rule_display() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    assert_eq!(sig.to_string(), rule.to_string());
}

#[test]
fn lowers_logical_ops_to_condition() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 2);
    assert_eq!(rule.condition, "($s0 and $s1)");
}

#[test]
fn reflects_target_description_filesize_range() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0,FileSize:10-20;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("filesize >= 10"));
    assert!(rule.condition.contains("filesize <= 20"));
}

#[test]
fn reflects_target_description_entrypoint_and_sections() {
    let sig = LogicalSignature::parse(
        "Foo.Bar-1;Target:1,EntryPoint:100-200,NumberOfSections:2-4;0;41414141",
    )
    .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.imports.iter().any(|i| i == "pe"));
    assert!(rule.condition.contains("pe.entry_point >= 100"));
    assert!(rule.condition.contains("pe.entry_point <= 200"));
    assert!(rule.condition.contains("pe.number_of_sections >= 2"));
    assert!(rule.condition.contains("pe.number_of_sections <= 4"));
}

#[test]
fn lowers_target_description_container_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1,Container:CL_TYPE_ZIP;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("Container=CL_TYPE_ZIP"))));
}

#[test]
fn lowers_target_description_intermediates_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1,Intermediates:1;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("Intermediates=1"))));
}

#[test]
fn lowers_match_count_expression() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)=1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "1 of ($s0, $s1)");
}

#[test]
fn lowers_multigt_for_single_subsig_with_occurrence_count() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0>2,1;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "#s0 > 2");
}

#[test]
fn lowers_multilt_for_single_subsig_with_occurrence_count() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0<3,1;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "#s0 < 3");
}

#[test]
fn lowers_multigt_for_group_as_distinct_approximation() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)>2,1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("1 of ($s0, $s1)"));
    assert!(rule.condition.contains("3 of ($s0, $s1)"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("multi-gt on grouped expression approximated"))));
}

#[test]
fn lowers_raw_subsignature_with_modifiers() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;hello::iwf").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule.strings.iter().any(
        |s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = \"hello\" nocase wide fullword")
    ));
}

#[test]
fn lowers_hex_subsignature_with_nocase_modifier() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = { (41|61) (42|62) (43|63) }")));
}

#[test]
fn lowers_multilt_for_group_as_distinct_approximation() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)<3,1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("1 of ($s0, $s1)"));
    assert!(rule.condition.contains("not (3 of ($s0, $s1))"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("multi-lt on grouped expression approximated"))));
}

#[test]
fn lowers_pcre_subsignature_with_nocase() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = /abc/ nocase")));
}

#[test]
fn lowers_pcre_trigger_prefix_to_condition() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("$s1"));
    assert!(rule.condition.contains("$s0"));
    assert!(rule.condition.contains("and"));
}

#[test]
fn lowers_pcre_offset_with_rolling_flag() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/r").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= 10"));
}

#[test]
fn lowers_pcre_encompass_with_range_offset() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= 200"));
    assert!(rule.condition.contains("@s1[j] <= 500"));
}

#[test]
fn lowers_pcre_range_offset_without_e_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("maxshift present without 'e'; lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_flag_e_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/E").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre flag 'E' unsupported; lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_inline_flags_for_dotall_multiline() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/sm").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = /(?sm:abc)/")));
}

#[test]
fn lowers_pcre_inline_flag_extended_mode() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/a b c/x").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = /(?x:a b c)/")));
}

#[test]
fn lowers_pcre_inline_flag_ungreedy_mode() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/a.+b/U").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = /(?U:a.+b)/")));
}

#[test]
fn lowers_byte_comparison_with_value_check() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>26#ib2#>512)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert!(rule.condition.contains("for any j in (1..#s0)"));
    assert!(rule.condition.contains("uint16be(@s0[j] + 26) > 512"));
    assert!(rule.condition.contains("(@s0[j] + 26) + 2 <= filesize"));
}

#[test]
fn lowers_byte_comparison_non_raw_hex_exact_eq() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#he4#=1A2B)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 0) == 0x31"));
    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 1) == 0x41"));
    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 1) == 0x61"));
    assert!(rule.condition.contains("(@s0[j] + 4) + 4 <= filesize"));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_exact_eq() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#de3#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 0) == 0x30"));
    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 1) == 0x31"));
    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 2) == 0x32"));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_exact_gt() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#de3#>12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for any j in (1..#s0)"));
    assert!(rule.condition.contains("(@s0[j] + 4) + 3 <= filesize"));
    assert!(rule.condition.contains("uint8((@s0[j] + 4) + 0)"));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_with_hex_alpha_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#de3#>A0)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("decimal base cannot use hex-alpha threshold token")
    )));
}

#[test]
fn lowers_byte_comparison_non_raw_hex_exact_lt() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>2#he2#<A0)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for any j in (1..#s0)"));
    assert!(rule.condition.contains("(@s0[j] + 2) + 2 <= filesize"));
    assert!(rule.condition.contains("0x41") || rule.condition.contains("0x61"));
}

#[test]
fn lowers_byte_comparison_non_raw_non_exact_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>26#db2#>512)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("non-exact unsupported; lowered to false for safety"))));
}

#[test]
fn lowers_byte_comparison_non_raw_little_endian_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#hle2#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("little-endian unsupported; lowered to false for safety"))));
}

#[test]
fn lowers_byte_comparison_raw_variable_size_with_shift_expr() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#ib3#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for any j in (1..#s0)"));
    assert!(rule.condition.contains("(@s0[j] + 4) + 3 <= filesize"));
    assert!(rule.condition.contains("<< 16"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_raw_unsupported_size_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#ib9#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("raw size 9 unsupported") && value.contains("lowered to false for safety"))));
}

#[test]
fn lowers_byte_comparison_raw_out_of_range_threshold_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>2#ib1#<300)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("raw threshold 300 exceeds 1-byte range") && value.contains("lowered to false for safety"))));
}

#[test]
fn lowers_byte_comparison_raw_contradictory_clauses_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>2#ib2#>512,<100)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("clauses are contradictory") && value.contains("lowered to false for safety"))));
}

#[test]
fn lowers_byte_comparison_non_raw_contradictory_clauses_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>3#de3#>200,<100)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("clauses are contradictory") && value.contains("lowered to false for safety"))));
}

#[test]
fn lowers_macro_subsignature_as_positional_constraint() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert!(rule.condition.contains("for any i in (1..#s0)"));
    assert!(rule.condition.contains("@s0[j] >= @s0[i] + 6"));
    assert!(rule.condition.contains("@s0[j] <= @s0[i] + 7"));
}

#[test]
fn lowers_fuzzy_img_as_safe_false() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes" && value.contains("fuzzy_img")
    )));
}

#[test]
fn lowers_ndb_basic_offset() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:0:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.name, "Win_Trojan_Example_1");
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$a = { 41 42 43 44 }")));
    assert!(rule.condition.contains("$a at 0"));
}

#[test]
fn rejects_ndb_descending_absolute_offset_range_for_strictness() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:100,10:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($a and false)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("descending bounds") && value.contains("strict lowering"))));
}

#[test]
fn lowers_ndb_entrypoint_with_pe_import() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:1:EP+0,15:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("import \"pe\""));
    assert!(src.contains("pe.entry_point + 0"));
    assert!(src.contains("<= pe.entry_point + 0 + 15"));
}

#[test]
fn lowers_ndb_negative_jump_exactly() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{-15}BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("$a = { AA [0-15] BB }"));
    assert!(!src.contains("approximated"));
    assert_eq!(rule.condition, "$a");
}

#[test]
fn lowers_ndb_open_ended_jump() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{10-}BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("$a = { AA [10-] BB }"));
    assert_eq!(rule.condition, "$a");
}

#[test]
fn rejects_ndb_descending_positive_range_jump_for_strictness() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{10-5}BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("descending bounds") && value.contains("strict lowering"))));
}

#[test]
fn rejects_ndb_complex_signed_range_jump_for_strictness() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{-10-5}BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("signed range jump"))));
}

#[test]
fn lowers_ndb_target_type_html_with_constraint() {
    let sig = NdbSignature::parse("Html.Test-1:3:*:3c68746d6c3e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8(j) == 0x3C"));
    assert!(rule.condition.contains("for all i"));
    assert!(rule.condition.contains("for any r in (0..511)")); // root marker in early window
    assert!(rule.condition.contains("uint8((c) + 1) == 0x2F")); // close-tag marker (</...)
    assert!(rule.condition.contains("for any c in"));
    assert!(rule.condition.contains("for any r in (0..c)")); // root marker must appear before close marker
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("target_type=3"))));
}

#[test]
fn lowers_ndb_target_type_mail_with_constraint() {
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8((0) + 0) == 0x46"));
    assert!(rule.condition.contains("uint8((0) + 4) == 0x3A"));
    assert!(rule.condition.contains("0x52")); // R/r from Received:
    assert!(rule.condition.contains("for any h in")); // secondary headers required
    assert!(rule.condition.contains("for any s in")); // header/body separator required
    assert!(rule.condition.contains("<= s")); // secondary header must appear before separator
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("strict multi-header heuristic"))));
}

#[test]
fn lowers_ndb_target_type_graphics_with_magic_check() {
    let sig = NdbSignature::parse("Img.Test-1:5:*:89504e47").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0x474E5089"));
    assert!(rule.condition.contains("uint16(0) == 0xD8FF"));
}

#[test]
fn lowers_ndb_target_type_ascii_with_constraint() {
    let sig = NdbSignature::parse("Txt.Test-1:7:*:68656c6c6f").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for all i in (0..filesize-1)"));
    assert!(rule.condition.contains("uint8(i) >= 0x20"));
    assert!(rule.condition.contains("for any j in (0..filesize-1)"));
    assert!(rule.condition.contains("uint8(j) >= 0x41"));
    assert!(!rule.condition.contains("0..4095"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("full-file printable+alpha heuristic")
    )));
}

#[test]
fn lowers_ndb_target_type_8_to_false_for_safety() {
    let sig = NdbSignature::parse("Unknown.Test-1:8:*:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("target_type=8"))));
}

#[test]
fn lowers_ndb_target_type_13_plus_to_false_for_safety() {
    let sig = NdbSignature::parse("Unknown.Test-2:13:*:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("13+"))));
}
