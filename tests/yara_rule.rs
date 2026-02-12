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
fn lowers_pcre_exact_offset_as_equality_from_clamav_regex_fixture() {
    // ClamAV reference:
    // - unit_tests/clamscan/regex_test.py:127-129 (exact offset semantics)
    // - unit_tests/clamscan/regex_test.py:152-174 (offset=5, exact start position)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;68656c6c6f20;5:0/hello blee/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] == 5"));
    assert!(!rule.condition.contains("@s1[j] >= 5"));
}

#[test]
fn lowers_pcre_exact_offset_match_fixture_with_same_equality_constraint() {
    // ClamAV reference:
    // - unit_tests/clamscan/regex_test.py:170-183 (`5:0/llo blee/` expected match)
    // - unit_tests/clamscan/regex_test.py:152-166 (`5:0/hello blee/` expected non-match)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;68656c6c6f20;5:0/llo blee/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] == 5"));
    assert!(!rule.condition.contains("@s1[j] >= 5"));
}

#[test]
fn lowers_pcre_re_range_ignores_r_and_keeps_encompass_window_from_clamav_matcher_fixture() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:146-149 (Test10 uses `/atre/re` with offset `2,6`)
    // - unit_tests/check_matchers.c:497-503 (expected_result is enforced for pcre_testdata)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,6:0/atre/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= 2"));
    assert!(rule.condition.contains("@s1[j] <= 8"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre flag 'r' ignored when maxshift is present")
    )));
}

#[test]
fn lowers_pcre_re_range_nonmatch_fixture_to_narrow_encompass_window() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:146-149 (Test8: `/apie/re` with offset `2,2`, expected CL_SUCCESS)
    // - unit_tests/check_matchers.c:497-503 (expected_result is enforced for pcre_testdata)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,2:0/apie/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= 2"));
    assert!(rule.condition.contains("@s1[j] <= 4"));
    assert!(!rule.condition.contains("@s1[j] <= 8"));
}

#[test]
fn lowers_pcre_ep_plus_offset_prefix_to_entry_point_constraint() {
    // ClamAV reference:
    // - libclamav/matcher.c:355-367 (`EP+` parsed as CLI_OFF_EP_PLUS)
    // - libclamav/matcher.c:469-475 (recalc base: `exeinfo.ep + offdata[1]`)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP+10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.imports.iter().any(|import| import == "pe"));
    assert!(rule.condition.contains("@s1[j] == pe.entry_point + 10"));
}

#[test]
fn lowers_pcre_eof_minus_offset_prefix_to_filesize_constraint() {
    // ClamAV reference:
    // - libclamav/matcher.c:393-400 (`EOF-` parsed as CLI_OFF_EOF_MINUS)
    // - libclamav/matcher.c:465-468 (recalc base: `fsize - offdata[1]`)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] == filesize - 10"));
}

#[test]
fn lowers_pcre_ep_minus_offset_prefix_to_entry_point_constraint() {
    // ClamAV reference:
    // - libclamav/matcher.c:362-367 (`EP-` parsed as CLI_OFF_EP_MINUS)
    // - libclamav/matcher.c:473-475 (recalc base: `exeinfo.ep - offdata[1]`)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP-4:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.imports.iter().any(|import| import == "pe"));
    assert!(rule.condition.contains("@s1[j] == pe.entry_point - 4"));
}

#[test]
fn lowers_pcre_star_offset_prefix_to_unbounded_condition_and_ignores_re_flags() {
    // ClamAV reference: libclamav/matcher.c:350-354 (`*` parsed as CLI_OFF_ANY)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("$s1"));
    assert!(rule.condition.contains("$s0"));
    assert!(!rule.condition.contains("@s1[j]"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' ignored on '*' offset prefix")
                && value.contains("flag 'e' ignored: '*' offset has no maxshift")
    )));
}

#[test]
fn lowers_pcre_section_offset_prefix_with_encompass_window() {
    // ClamAV reference:
    // - libclamav/matcher.c:383-391 (`Sx+` parsed as CLI_OFF_SX_PLUS)
    // - libclamav/matcher.c:481-485 (recalc base: `sections[n].raw + offdata[1]`)
    // - libclamav/matcher-pcre.c:651-658 (`e` constrains scanning to offset..offset+maxshift)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S2+4,8:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.imports.iter().any(|import| import == "pe"));
    assert!(rule.condition.contains("pe.number_of_sections > 2"));
    assert!(rule
        .condition
        .contains("@s1[j] >= pe.sections[2].raw_data_offset + 4"));
    assert!(rule
        .condition
        .contains("@s1[j] <= pe.sections[2].raw_data_offset + 4 + 8"));
}

#[test]
fn lowers_pcre_last_section_offset_prefix_to_constraint() {
    // ClamAV reference:
    // - libclamav/matcher.c:377-382 (`SL+` parsed as CLI_OFF_SL_PLUS)
    // - libclamav/matcher.c:477-479 (recalc base: `sections[nsections-1].raw + offdata[1]`)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SL+16:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.imports.iter().any(|import| import == "pe"));
    assert!(rule.condition.contains("pe.number_of_sections > 0"));
    assert!(rule
        .condition
        .contains("@s1[j] == pe.sections[pe.number_of_sections - 1].raw_data_offset + 16"));
}

#[test]
fn lowers_pcre_section_end_offset_with_e_to_section_window() {
    // ClamAV reference:
    // - libclamav/matcher.c:369-376 (`SEn` parsed as CLI_OFF_SE)
    // - libclamav/matcher.c:487-495 (effective maxshift includes section raw size)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.imports.iter().any(|import| import == "pe"));
    assert!(rule.condition.contains("pe.number_of_sections > 1"));
    assert!(rule
        .condition
        .contains("@s1[j] >= pe.sections[1].raw_data_offset"));
    assert!(rule
        .condition
        .contains("@s1[j] <= pe.sections[1].raw_data_offset + pe.sections[1].raw_data_size + 4"));
}

#[test]
fn lowers_pcre_section_end_offset_without_e_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:369-376 (`SEn` parsed as CLI_OFF_SE)
    // - libclamav/matcher.c:487-495 (effective maxshift includes section raw size)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1:0/abc/").unwrap();
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
fn lowers_pcre_versioninfo_offset_prefix_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:401-403 (`VI` parsed as CLI_OFF_VERSION)
    // - libclamav/matcher-pcre.c:539 (`TODO - handle VI and Macro offset types`)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;VI:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("CLI_OFF_VERSION")
    )));
}

#[test]
fn lowers_pcre_non_numeric_offset_prefix_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:348-454 (`cli_caloff` accepts only numeric payloads for `EP+/-`, `Sx+`, `EOF-`).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP+foo:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix 'EP+foo' unsupported")
    )));
}

#[test]
fn lowers_pcre_macro_group_offset_prefix_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:431-442 (`$n$` parsed as CLI_OFF_MACRO) and
    // libclamav/matcher-ac.c:1908-1909 (runtime macro_lastmatch state).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$1$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.condition.contains("$s1"));
    assert!(rule.condition.contains("$s0"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset `$1$` depends on CLI_OFF_MACRO runtime state")
    )));
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
fn lowers_pcre_unsupported_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/d").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("unsupported pcre flag(s) 'd'; lowered to false for safety")
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
fn lowers_macro_subsignature_to_false_for_safety_with_macro_group_note() {
    // ClamAV reference (source semantics):
    // - libclamav/readdb.c:442-512 parses `${min-max}group$` and stores group id (not subsig index)
    // - libclamav/matcher-ac.c:1757-1796 resolves macro via runtime `macro_lastmatch[group]`
    // We cannot represent that runtime macro-group state in standalone YARA, so keep safety-false.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 or false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("macro-group `$0$` semantics depend on CLI_OFF_MACRO")
    )));
}

#[test]
fn lowers_macro_descending_range_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${7-6}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 or false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("macro descending range 7-6 unsupported; lowered to false for safety")
    )));
}

#[test]
fn lowers_macro_invalid_format_to_false_for_safety() {
    // ClamAV reference: libclamav/readdb.c:463 rejects invalid macro format unless `${min-max}group$`.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 or false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("macro subsignature format unsupported/invalid")
    )));
}

#[test]
fn lowers_macro_group_out_of_range_to_false_for_safety() {
    // ClamAV reference: libclamav/readdb.c:469, libclamav/matcher.c:438 (only 32 macro groups).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}32$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 or false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("macro group 32 out of range")
    )));
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
fn lowers_fuzzy_img_with_second_subsig_to_safe_false_from_clamav_fixture() {
    // ClamAV reference: unit_tests/clamscan/fuzzy_img_hash_test.py:40-42,54-61
    // (`logo.png.good.with.second.subsig` / `logo.png.bad.with.second.subsig`)
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;49484452;fuzzy_img#af2ad01ed42993c7#0")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img hash 'af2ad01ed42993c7' is not representable in YARA")
    )));
}

#[test]
fn lowers_fuzzy_img_nonzero_distance_to_safe_false_with_note_from_clamav_fixture() {
    // ClamAV reference: unit_tests/clamscan/fuzzy_img_hash_test.py:116-132
    // (`fuzzy_img#...#1` is rejected as invalid hamming distance)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#1").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img distance=1 unsupported; lowered to false")
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
fn lowers_ndb_absolute_range_offset_at_boundary_when_representable() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:1,1:4142").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("$a in (1..1)"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_ndb_malformed_absolute_range_offset_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:365-381 (`cli_caloff` only accepts numeric `n[,maxshift]`).
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:1,:4142").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($a and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("offset format is unsupported: 1,")
                && value.contains("forcing condition=false")
    )));
}

#[test]
fn lowers_ndb_ep_offset_without_explicit_sign_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:384-395 (`cli_caloff` accepts only `EP+<num>` / `EP-<num>`).
    let sig = NdbSignature::parse("Win.Trojan.Example-1:1:EP10:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("offset format is unsupported: EP10")
    )));
}

#[test]
fn lowers_ndb_eof_plus_offset_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:422-428 (`cli_caloff` accepts only `EOF-<num>`).
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:EOF+10:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($a and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("offset format is unsupported: EOF+10")
    )));
}

#[test]
fn lowers_ndb_relative_offset_on_non_exec_target_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:453-457 (`cli_caloff`: EP/Sx/SE/SL offsets require PE/ELF/Mach-O target)
    // - libclamav/matcher.h:205-213 (`TARGET_GENERIC=0`, executable targets are 1/6/9)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:EP+10:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($a and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("invalid for target_type=0")
                && value.contains("PE/ELF/MachO")
    )));
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
fn rejects_ndb_signed_negative_jump_for_strictness() {
    // ClamAV reference:
    // - libclamav/readdb.c:727-731,851-874 (`{n}` / `{min-max}` parses unsigned distances)
    // Signed jumps are not representable in ClamAV body wildcard grammar; keep strict safety-false.
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{-15}BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("signed jump")
                && value.contains("strict lowering")
    )));
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
fn lowers_ndb_square_exact_range_jump_within_clamav_maxdist() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2751-2786 (`[n]` / `[n-m]`, ascending only)
    // - libclamav/matcher-ac.h:32 (`AC_CH_MAXDIST` == 32)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[2-4]BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("$a = { AA [2-4] BB }"));
    assert_eq!(rule.condition, "$a");
}

#[test]
fn rejects_ndb_square_descending_range_jump_for_strictness() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[10-5]BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("[] jump")
                && value.contains("descending bounds")
                && value.contains("strict lowering")
    )));
}

#[test]
fn rejects_ndb_square_open_or_signed_bounds_for_strictness() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[-5]BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("[] jump")
                && value.contains("open/signed bounds")
                && value.contains("strict lowering")
    )));
}

#[test]
fn rejects_ndb_square_jump_over_clamav_maxdist_for_strictness() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[33]BB").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("AC_CH_MAXDIST=32")
                && value.contains("strict lowering")
    )));
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
    // ClamAV reference:
    // - libclamav/scanners.c:2563-2589 (target HTML scans run on normalized `nocomment.html` / `notags.html`)
    // - libclamav/htmlnorm.c:962-1000 (tag tokenization ends on `>`/whitespace)
    // - libclamav/htmlnorm.c:1229-1249 (closing tag handling uses exact parsed tag token)
    let sig = NdbSignature::parse("Html.Test-1:3:*:3c68746d6c3e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8(j) == 0x3C"));
    assert!(rule.condition.contains("for all i"));
    assert!(rule.condition.contains("for any r in (0..511)")); // root marker in early window
    assert!(rule.condition.contains("uint8((c) + 1) == 0x2F")); // close-tag marker (</...)
    assert!(rule.condition.contains("for any c in"));
    assert!(rule.condition.contains("for any r in (0..c)")); // root marker must appear before close marker

    // Strict boundary checks: marker must be followed by tag terminator (`>` or ASCII whitespace).
    assert!(rule.condition.contains("r + 5 < 512"));
    assert!(rule.condition.contains("uint8((r) + 5) == 0x3E"));
    assert!(rule.condition.contains("c + 6 < 4096"));
    assert!(rule.condition.contains("uint8((c) + 6) == 0x3E"));
    assert!(!rule.condition.contains("r + 5 <= 512"));
    assert!(!rule.condition.contains("c + 6 <= 4096"));

    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("target_type=3")
                && value.contains("tag terminator + order")
    )));
}

#[test]
fn lowers_ndb_target_type_mail_with_constraint() {
    // ClamAV reference:
    // - libclamav/mbox.c:1173-1183 (blank line marks header/body boundary)
    // - libclamav/mbox.c:1263-1268,1330-1391 (header lines are parsed as header entries before body)
    // - libclamav/mbox.c:1310-1316 (no parsed headers => not treated as email)
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8((0) + 0) == 0x46"));
    assert!(rule.condition.contains("uint8((0) + 4) == 0x3A"));
    assert!(rule.condition.contains("0x52")); // R/r from Received:
    assert!(rule.condition.contains("for any h in")); // secondary headers required
    assert!(rule.condition.contains("for any s in")); // header/body separator required
    assert!(rule.condition.contains("<= s")); // secondary header must appear before separator
    assert!(rule
        .condition
        .contains("(h) == 0 or ((h) > 0 and uint8((h) - 1) == 0x0A)")); // secondary header must be line-start
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("line-start + secondary-header-before-separator"))));
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
    // ClamAV reference:
    // - libclamav/textnorm.c:64-68 (text normalization contract: whitespace fold + lowercase)
    // - libclamav/textnorm.c:74-82 (`A32` table entries map 'A'..'Z' to lowercase)
    // - libclamav/textnorm.c:115-129 (NORMALIZE_ADD_32 applies uppercase->lowercase)
    let sig = NdbSignature::parse("Txt.Test-1:7:*:68656c6c6f").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for all i in (0..filesize-1)"));
    assert!(rule.condition.contains("uint8(i) >= 0x20"));
    assert!(rule.condition.contains("for any j in (0..filesize-1)"));
    assert!(rule.condition.contains("uint8(j) >= 0x61"));
    assert!(rule.condition.contains("for all k in (0..filesize-1)"));
    assert!(rule
        .condition
        .contains("not ((uint8(k) >= 0x41 and uint8(k) <= 0x5A))"));
    assert!(!rule.condition.contains("0..4095"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("normalized-text heuristic")
    )));
}

#[test]
fn lowers_ndb_target_type_8_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.h:205-219 (`TARGET_NOT_USED = 8`).
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
    // ClamAV reference: libclamav/matcher.h:218-219 (`TARGET_INTERNAL = 13`, `TARGET_OTHER = 14`).
    let sig = NdbSignature::parse("Unknown.Test-2:13:*:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("13+"))));
}

#[test]
fn lowers_ndb_target_type_14_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.h:218-219 (`TARGET_INTERNAL` / `TARGET_OTHER` are not user DB targets).
    let sig = NdbSignature::parse("Unknown.Test-3:14:*:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("target_type=14")
                && value.contains("13+")
    )));
}

#[test]
fn lowers_ndb_non_numeric_target_type_to_false_for_safety() {
    // ClamAV reference: libclamav/readdb.c:1714-1716 (`target` field must be `*` or numeric).
    let sig = NdbSignature::parse("Unknown.Test-4:foo:*:41424344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("target_type=foo")
                && value.contains("invalid/unknown")
    )));
}
