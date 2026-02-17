use sig2yar::parser::{
    cbc::CbcSignature, cdb::CdbSignature, cfg::CfgSignature, crb::CrbSignature, fp::FpSignature,
    ftm::FtmSignature, hdu::HduSignature, hsu::HsuSignature, idb::IdbSignature, ign::IgnSignature,
    ign2::Ign2Signature, info::InfoSignature, ldu::LduSignature, logical::LogicalSignature,
    mdu::MduSignature, msu::MsuSignature, ndb::NdbSignature, ndu::NduSignature, pdb::PdbSignature,
    sfp::SfpSignature, wdb::WdbSignature,
};
use sig2yar::yara::{self, YaraMeta, YaraRule, YaraString};

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
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_unsupported" && value == "target_description_container_constraint")));
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
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_unsupported" && value == "target_description_intermediates_constraint")));
}

#[test]
fn lowers_target_description_engine_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Engine:51-255,Target:1;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("Engine=51-255"))));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_unsupported" && value == "target_description_engine_constraint")));
}

#[test]
fn lowers_target_description_icon_group_constraints_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1,IconGroup1:foo,IconGroup2:bar;0;41414141")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("IconGroup1=foo"))));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("IconGroup2=bar"))));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_unsupported" && value == "target_description_icon_group1_constraint")));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_unsupported" && value == "target_description_icon_group2_constraint")));
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
fn lowers_multigt_for_group_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)>2,1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("multi-gt grouped expression unsupported for strict lowering"))));
}

#[test]
fn lowers_multigt_for_single_subsig_with_distinct_threshold_note() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0>2,2;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "#s0 > 2");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("multi-gt distinct threshold 2 ignored for single-subsig expression")
    )));
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
fn lowers_hex_subsignature_with_wide_modifier() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::w").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = { 41 00 42 00 43 00 }")));
}

#[test]
fn lowers_hex_subsignature_with_wide_ascii_modifier() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::wa").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule.strings.iter().any(
        |s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = { (41 42 43 | 41 00 42 00 43 00) }")
    ));
}

#[test]
fn lowers_hex_subsignature_with_wide_ascii_nocase_modifier() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::iwa").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s0 = { ((41|61) (42|62) (43|63) | (41|61) 00 (42|62) 00 (43|63) 00) }")));
}

#[test]
fn lowers_hex_subsignature_with_fullword_modifier_to_boundary_condition() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;68656c6c6f::f").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for any i in (1..#s0)"));
    assert!(rule.condition.contains("uint8((@s0[i]) - 1)"));
    assert!(rule.condition.contains("uint8(@s0[i] + !s0[i])"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("hex modifier 'f' lowered with strict non-alphanumeric boundary checks")
    )));
}

#[test]
fn lowers_hex_subsignature_with_wide_fullword_modifier_to_boundary_condition() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;68656c6c6f::wf").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for any i in (1..#s0)"));
    assert!(rule.condition.contains("uint8((@s0[i]) - 2)"));
    assert!(rule.condition.contains("uint8((@s0[i]) - 1) == 0x00"));
    assert!(rule.condition.contains("uint8(@s0[i] + !s0[i])"));
    assert!(rule
        .condition
        .contains("uint8((@s0[i] + !s0[i]) + 1) == 0x00"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("hex modifier 'f' lowered with strict wide alnum+NUL boundary checks")
    )));
}

#[test]
fn lowers_hex_subsignature_with_wide_ascii_fullword_modifier_to_branch_dispatched_boundary_condition(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;68656c6c6f::waf").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("for any i in (1..#s0)"));
    assert!(rule.condition.contains("!s0[i] == 5"));
    assert!(rule.condition.contains("!s0[i] == 10"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("hex modifier 'f' lowered with strict ascii|wide branch-dispatched boundary checks")
    )));
}

#[test]
fn lowers_multilt_for_group_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)<3,1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("multi-lt grouped expression unsupported for strict lowering"))));
}

#[test]
fn lowers_multilt_for_single_subsig_with_distinct_threshold_note() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0<3,2;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "#s0 < 3");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("multi-lt distinct threshold 2 ignored for single-subsig expression")
    )));
}

#[test]
fn lowers_multilt_for_group_with_incompatible_distinct_to_false() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)<3,3;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("multi-lt distinct threshold 3 is incompatible with <3")
    )));
}

#[test]
fn lowers_pcre_subsignature_with_nocase() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("$s0"));
    assert!(rule.condition.contains("$s1"));
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s1 = /abc/ nocase")));
}

#[test]
fn lowers_pcre_self_referential_trigger_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher-pcre.c:232-239 rejects self-referential PCRE triggers.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("self-referential")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_mixed_self_reference_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher-pcre.c:232-239 rejects self-referential PCRE triggers.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0|1/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("self-referential")
                && value.contains("lowered to false for safety")
    )));
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
fn lowers_pcre_trigger_prefix_with_count_expression_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)=1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("count/distinct operators unsupported for strict lowering")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_match_range_expression_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)=1,2/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("count/distinct operators unsupported for strict lowering")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_multi_gt_expression_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)>1,1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("count/distinct operators unsupported for strict lowering")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_multi_lt_expression_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)<2,1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("count/distinct operators unsupported for strict lowering")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_gt_expression_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)>1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("count/distinct operators unsupported for strict lowering")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_lt_expression_to_false_for_safety() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)<2/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("count/distinct operators unsupported for strict lowering")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_missing_reference_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;9/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("references unsupported/missing subsig index(es) 9")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_false_subsig_dependency_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;fuzzy_img##0;0:0/xyz/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("trigger expression resolved to false")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_trigger_expression_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;200,300:/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre trigger prefix parse failed")
                && value.contains("missing trigger expression after ':'")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_malformed_trigger_expression_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;200,300:foo/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_malformed_offset_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,abc:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,abc' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_maxshift_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_base_offset_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',300' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_spaced_range_offset_without_e_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141; 200 , 300 :0/abc/").unwrap();
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
fn lowers_pcre_trigger_prefix_with_extra_comma_offset_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300,400:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,300,400' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_empty_middle_offset_token_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,,300' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_trailing_comma_offset_token_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,300,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_double_leading_comma_offset_token_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',,300' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_multi_empty_comma_offset_token_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,,,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,,,300' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_trailing_multi_empty_comma_offset_token_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300,,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '200,300,,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_base_and_trailing_comma_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,300,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',300,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_base_and_trailing_multi_empty_comma_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,300,,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',300,,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_double_leading_and_trailing_comma_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,,300,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',,300,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_base_and_double_trailing_empty_comma_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,300,,,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',300,,,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_double_leading_and_trailing_multi_empty_comma_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,,300,,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',,300,,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_base_and_trailing_multi_empty_comma_without_maxshift_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;300,,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '300,,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_all_empty_comma_tokens_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,,,:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',,,' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_base_empty_middle_and_numeric_tail_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;300,,400:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '300,,400' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_base_empty_middle_and_numeric_tail_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,300,,400:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',300,,400' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_base_multi_empty_middle_and_numeric_tail_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;300,,,400:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '300,,,400' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_missing_base_multi_empty_middle_and_numeric_tail_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,300,,,400:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',300,,,400' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_comma_only_multi_empty_and_numeric_tail_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;,,,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix ',,,300' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_base_deep_empty_middle_and_numeric_tail_offset_token_to_false_for_safety(
) {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;300,,,,400:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '300,,,,400' unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_trigger_prefix_with_mixed_missing_reference_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;0|9/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("references unsupported/missing subsig index(es) 9")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_malformed_pcre_subsignature_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/readdb.c routes subsignatures containing '/' to PCRE loader path
    //   before plain content-match handling.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre subsignature format unsupported/invalid")
    )));
}

#[test]
fn lowers_pcre_offset_with_rolling_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/r").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with exact offset prefix")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_re_flags_without_offset_prefix_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag(s) 'r', 'e' require explicit offset/maxshift runtime semantics")
    )));
}

#[test]
fn lowers_pcre_r_flag_without_offset_prefix_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/abc/r").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag(s) 'r' require explicit offset/maxshift runtime semantics")
    )));
}

#[test]
fn lowers_pcre_e_flag_without_offset_prefix_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag(s) 'e' require explicit offset/maxshift runtime semantics")
    )));
}

#[test]
fn lowers_pcre_exact_offset_with_encompass_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'e' with exact offset prefix")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_exact_offset_with_re_flags_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with exact offset prefix")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_anchored_with_offset_prefix_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher-pcre.c uses offset-adjusted scan start, and anchored matching is relative
    //   to runtime scan position rather than global file start.
    // - standalone YARA `\\A` anchors only to file start, so offset-prefixed anchored semantics
    //   are not safely equivalent.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/A").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("anchored flag with explicit offset prefix cannot be represented safely")
    )));
}

#[test]
fn lowers_pcre_anchored_with_offset_prefix_and_encompass_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/Ae").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("anchored flag with explicit offset prefix cannot be represented safely")
    )));
}

#[test]
fn lowers_pcre_anchored_with_offset_prefix_and_rolling_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/Ar").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("anchored flag with explicit offset prefix cannot be represented safely")
    )));
}

#[test]
fn lowers_pcre_anchored_with_offset_prefix_and_re_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/Are").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("anchored flag with explicit offset prefix cannot be represented safely")
    )));
}

#[test]
fn lowers_pcre_anchored_with_rolling_or_encompass_to_false_for_safety() {
    // ClamAV reference:
    // - `A` anchoring and `r/e` scan-behavior flags are evaluated in ClamAV matcher runtime state.
    // - standalone YARA cannot safely preserve this combined flag interaction.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/Ar").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("anchored flag combined with rolling/encompass flags is not representable safely")
    )));
}

#[test]
fn lowers_pcre_anchored_with_encompass_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/Ae").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("anchored flag combined with rolling/encompass flags is not representable safely")
    )));
}

#[test]
fn lowers_pcre_anchored_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/A").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre anchored flag is not representable safely in standalone YARA")
    )));
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
fn lowers_pcre_re_range_to_false_for_safety() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:146-149 (Test10 uses `/atre/re` with offset `2,6`)
    // - unit_tests/check_matchers.c:497-503 (expected_result is enforced for pcre_testdata)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,6:0/atre/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_re_range_nonmatch_fixture_to_false_for_safety() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:146-149 (Test8: `/apie/re` with offset `2,2`, expected CL_SUCCESS)
    // - unit_tests/check_matchers.c:497-503 (expected_result is enforced for pcre_testdata)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,2:0/apie/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_encompass_window_with_match_end_guard_from_clamav_fixture() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:144 (Test7 `/34567890/e` with `3,7`, expected CL_SUCCESS)
    // - libclamav/matcher-pcre.c:624-629 (`e` bounds adjlength to adjshift)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;6E6F74;3,7:0/34567890/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= 3"));
    assert!(rule.condition.contains("(@s1[j] + !s1[j]) <= 10"));
    assert!(!rule.condition.contains("@s1[j] <= 10"));
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
fn lowers_pcre_ep_plus_offset_prefix_with_rolling_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP+10,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_ep_offset_prefix_on_non_exec_target_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:455-459 rejects EP/Sx/SE/SL offsets unless target is PE/ELF/MachO.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;EP+10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix 'EP+/-' is invalid for target_type=any")
                && value.contains("EP/Sx/SE/SL offsets only for PE/ELF/MachO")
    )));
}

#[test]
fn lowers_pcre_section_offset_prefix_on_non_exec_target_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:455-459 rejects EP/Sx/SE/SL offsets unless target is PE/ELF/MachO.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;S2+4,8:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix 'Sx+' is invalid for target_type=any")
                && value.contains("EP/Sx/SE/SL offsets only for PE/ELF/MachO")
    )));
}

#[test]
fn lowers_pcre_last_section_offset_prefix_on_non_exec_target_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:455-459 rejects EP/Sx/SE/SL offsets unless target is PE/ELF/MachO.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;SL+16:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix 'SL+' is invalid for target_type=any")
                && value.contains("EP/Sx/SE/SL offsets only for PE/ELF/MachO")
    )));
}

#[test]
fn lowers_pcre_section_entire_offset_prefix_on_non_exec_target_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:455-459 rejects EP/Sx/SE/SL offsets unless target is PE/ELF/MachO.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;SE1,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix 'SE' is invalid for target_type=any")
                && value.contains("EP/Sx/SE/SL offsets only for PE/ELF/MachO")
    )));
}

#[test]
fn lowers_pcre_eof_minus_encompass_window_with_match_end_guard() {
    // ClamAV reference:
    // - libclamav/matcher.c:393-400 (`EOF-` parsed as CLI_OFF_EOF_MINUS)
    // - libclamav/matcher-pcre.c:624-629 (`e` bounds adjlength to adjshift)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-5,3:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= filesize - 5"));
    assert!(rule
        .condition
        .contains("(@s1[j] + !s1[j]) <= filesize - 5 + 3"));
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
fn lowers_pcre_eof_minus_offset_prefix_with_rolling_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-10,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
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
fn lowers_pcre_ep_minus_offset_prefix_with_rolling_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP-10,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_star_offset_prefix_with_re_flags_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:350-354 (`*` parsed as CLI_OFF_ANY)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag(s) 'r', 'e' on '*' offset prefix")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_star_offset_prefix_with_r_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*:0/abc/r").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag(s) 'r' on '*' offset prefix")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_star_offset_prefix_with_e_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag(s) 'e' on '*' offset prefix")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_star_with_maxshift_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:360-363 accepts only exact "*" for CLI_OFF_ANY.
    // - forms like "*,10" are malformed (fall through to invalid absolute parse).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*,10:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset prefix '*,10' unsupported")
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
        .contains("(@s1[j] + !s1[j]) <= pe.sections[2].raw_data_offset + 4 + 8"));
}

#[test]
fn lowers_pcre_section_offset_prefix_with_rolling_flag_to_false_for_safety() {
    // ClamAV reference:
    // - libclamav/matcher.c:383-391 (`Sx+` parsed as CLI_OFF_SX_PLUS)
    // - libclamav/matcher-pcre.c rolling mode is runtime scan-state dependent.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S2+4,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
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
fn lowers_pcre_last_section_offset_prefix_with_rolling_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SL+16,4:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
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
    assert!(rule.condition.contains(
        "(@s1[j] + !s1[j]) <= pe.sections[1].raw_data_offset + pe.sections[1].raw_data_size + 4"
    ));
}

#[test]
fn lowers_pcre_section_end_offset_with_rolling_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1,4:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("flag 'r' with maxshift")
                && value.contains("lowered to false for safety")
    )));
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
fn lowers_pcre_versioninfo_prefixed_payload_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:401-403 uses `strncmp(offcpy, "VI", 2)`.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;VIjunk:0/abc/").unwrap();
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
fn lowers_pcre_macro_group_offset_prefix_with_trailing_bytes_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c uses sscanf("$%u$") for macro group offset;
    // trailing bytes after closing '$' are tolerated by sscanf and still parse as CLI_OFF_MACRO.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$12$junk:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre offset `$12$` depends on CLI_OFF_MACRO runtime state")
    )));
}

#[test]
fn lowers_pcre_macro_group_offset_prefix_without_closing_dollar_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$12:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre macro offset '$12' has invalid format")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_macro_group_offset_prefix_without_digits_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre macro offset '$$' has invalid format")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_macro_group_offset_prefix_with_space_after_dollar_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$ 12$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre macro offset '$ 12$' has invalid format")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_macro_group_offset_prefix_with_space_before_closing_dollar_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$12 $:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre macro offset '$12 $' has invalid format")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_invalid_macro_group_offset_prefix_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:432-434 rejects malformed `$...$` offsets.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$foo$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre macro offset '$foo$' has invalid format")
    )));
}

#[test]
fn lowers_pcre_out_of_range_macro_group_offset_prefix_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher.c:431-442 accepts only macro groups 0..31.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$32$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("(false)"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("pcre macro-group offset `$32$` out of range")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_encompass_with_range_offset() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s1[j] >= 200"));
    assert!(rule.condition.contains("(@s1[j] + !s1[j]) <= 500"));
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
fn lowers_pcre_global_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/g").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("unsupported pcre flag(s) 'g'; lowered to false for safety")
    )));
}

#[test]
fn lowers_pcre_legacy_a_flag_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/a").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("unsupported pcre flag(s) 'a'; lowered to false for safety")
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
fn lowers_pcre_python_named_syntax_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/(?P=funcname)/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("Python-style named capture/backreference syntax")
    )));
}

#[test]
fn lowers_pcre_inline_flags_for_dotall_multiline() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/abc/sm").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s1 = /(?sm:abc)/")));
}

#[test]
fn lowers_pcre_inline_flag_extended_mode() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/a b c/x").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s1 = /(?x:a b c)/")));
}

#[test]
fn lowers_pcre_inline_flag_ungreedy_mode() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/a.+b/U").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$s1 = /(?U:a.+b)/")));
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
fn lowers_byte_comparison_offset_with_0x_prefix() {
    // ClamAV reference: libclamav/matcher-byte-comp.c parses offset using strtol(..., 0).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0xA#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s0[j] + 10"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_offset_with_explicit_plus_sign() {
    // ClamAV `strtol(..., 0)` accepts optional '+' prefix.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>+0xA#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s0[j] + 10"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_offset_with_plus_prefixed_octal_token() {
    // ClamAV `strtol(..., 0)` interprets +010 as octal (=8).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>+010#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s0[j] + 8"));
    assert!(!rule.condition.contains("@s0[j] + 10"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_offset_with_plus_invalid_octal_token_to_false_for_safety() {
    // ClamAV base-0 parse treats +08 as invalid octal.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>+08#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("byte_comparison format unsupported/invalid")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_byte_comparison_offset_with_bare_hex_token_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0A#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("byte_comparison format unsupported/invalid")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_byte_comparison_offset_with_octal_token() {
    // ClamAV reference: libclamav/matcher-byte-comp.c parses offset using strtol(..., 0),
    // so `010` is interpreted as octal (= 8).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>010#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("@s0[j] + 8"));
    assert!(!rule.condition.contains("@s0[j] + 10"));
    assert!(!rule.condition.contains("and false"));
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
fn lowers_byte_comparison_non_raw_hex_numeric_threshold_as_hex_value() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0#he2#=10)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    // base=`h` should interpret numeric threshold tokens as hex values.
    // `=10` means 0x10, so the textual hex comparison should target "10" (0x31,0x30),
    // not "0A".
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 0) == 0x31"));
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x30"));
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
fn lowers_byte_comparison_non_raw_decimal_with_0x_prefixed_threshold() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3130;0(>>0#de2#=0xA)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    // `0xA` should be parsed as decimal 10, then represented in decimal textual width=2 => "10".
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 0) == 0x31"));
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x30"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_with_plus_prefixed_0x_threshold() {
    // ClamAV `strtol(..., 0)` accepts optional '+' prefix for compare values.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3130;0(>>0#de2#=+0xA)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 0) == 0x31"));
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x30"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_with_plus_prefixed_octal_threshold() {
    // ClamAV `strtol(..., 0)` interprets +010 as octal (=8).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=+010)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 0) == 0x30"));
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x38"));
    assert!(!rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x30")); // avoid accidental "10"
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_with_leading_zero_octal_threshold() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=010)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    // ClamAV compare value parse uses base-0: `010` => octal 8, so width=2 decimal text is "08".
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 0) == 0x30"));
    assert!(rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x38"));
    assert!(!rule.condition.contains("uint8((@s0[j] + 0) + 1) == 0x30")); // avoid accidental "10"
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_invalid_octal_threshold_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=08)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("byte_comparison format unsupported/invalid")
    )));
}

#[test]
fn lowers_byte_comparison_non_raw_decimal_plus_invalid_octal_threshold_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=+08)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("byte_comparison format unsupported/invalid")
    )));
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
                && value.contains("decimal base cannot use bare hex-alpha threshold token")
    )));
}

#[test]
fn lowers_byte_comparison_non_raw_auto_base_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0#ae2#=10)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("non-raw auto base unsupported for strict lowering")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_byte_comparison_non_raw_hex_width_over_clamav_limit_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher-byte-comp.h (`CLI_BCOMP_MAX_HEX_BLEN = 18`).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0#he19#=1)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("non-raw hex width 19 exceeds ClamAV limit 18")
                && value.contains("lowered to false for safety")
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
fn lowers_byte_comparison_raw_size_3_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher-byte-comp.c accepts binary byte_len only in {1,2,4,8}.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#ib3#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("raw size 3 unsupported")
                && value.contains("supports only 1/2/4/8 bytes")
                && value.contains("lowered to false for safety")
    )));
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
fn lowers_byte_comparison_with_more_than_two_clauses_to_false_for_safety() {
    // ClamAV reference: libclamav/matcher-byte-comp.c accepts at most one comma
    // in byte-compare comparisons (`comp_count` is 1 or 2 only).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>3#de3#>100,<900,=123)")
        .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("byte_comparison with 3 clauses unsupported")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_byte_comparison_negative_threshold_to_false_for_safety() {
    // ClamAV source parses comparison values as signed (`strtoll`).
    // Current strict-safe lowering does not model signed extraction semantics.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>3#ib2#>-1)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("negative comparison value unsupported for strict lowering")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_invalid_byte_comparison_format_to_false_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#he2#=1G)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert_eq!(rule.strings.len(), 1);
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("byte_comparison format unsupported/invalid")
                && value.contains("lowered to false for safety")
    )));
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
fn lowers_macro_missing_trailing_dollar_to_false_for_safety() {
    // ClamAV reference: libclamav/readdb.c:463 rejects invalid macro format unless `${min-max}group$`.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}0").unwrap();
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
fn lowers_macro_subsignature_with_linked_ndb_group_when_representable() {
    // ClamAV reference: docs LogicalSignatures macro example (`${6-7}12$` + `test.ndb` `$12`).
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:0:$12:626262").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:636363").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$m1_0 = { 62 62 62 }")));
    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$m1_1 = { 63 63 63 }")));
    assert!(rule.condition.contains("for any i in (1..#s0)"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(rule.condition.contains("@m1_0[j] <= @s0[i] + 7"));
    assert!(!rule.condition.contains("and false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("macro-group `$12$` resolved via linked ndb members [D1, D2]")
    )));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_1_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:1:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("uint16(0) == 0x5A4D"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_2_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:2:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule
        .condition
        .contains("uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_3_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:3:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule
        .condition
        .contains("for any j in (0..filesize-1) : (uint8(j) == 0x3C)"));
    assert!(rule
        .condition
        .contains("for any k in (0..filesize-1) : (uint8(k) == 0x3E)"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_4_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:4:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("for any s in (0..filesize-1)"));
    assert!(rule.condition.contains("for any h in (0..s)"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_5_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:5:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0x474E5089"));
    assert!(rule.condition.contains("uint16(0) == 0xD8FF"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_6_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:6:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0x464C457F"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_7_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:7:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("for all i in (0..filesize-1)"));
    assert!(rule.condition.contains("for all k in (0..filesize-1)"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_9_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:9:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0xCEFAEDFE"));
    assert!(rule.condition.contains("uint32(0) == 0xCAFEBABE"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_10_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:10:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0x46445025"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_11_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:11:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule
        .condition
        .contains("(uint8(0) == 0x46 or uint8(0) == 0x43 or uint8(0) == 0x5A)"));
    assert!(rule
        .condition
        .contains("uint8(1) == 0x57 and uint8(2) == 0x53"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_with_linked_ndb_target_type_12_when_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:12:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0xBEBAFECA"));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(rule.condition.contains("@m1_0[j] >= @s0[i] + 6"));
    assert!(!rule.condition.contains("and false"));
}

#[test]
fn lowers_macro_subsignature_to_false_when_linked_ndb_is_not_strictly_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:8:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("target_type=8 (expected 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, or 12)")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_macro_subsignature_to_false_when_linked_ndb_group_is_out_of_range() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:0:$32:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("offset group $32 outside 0..31")
                && value.contains("macro-group `$12$` semantics depend on CLI_OFF_MACRO")
    )));
}

#[test]
fn lowers_macro_subsignature_to_false_when_linked_ndb_body_is_not_representable() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:0:$12:AA{-15}BB").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("ndb macro link 'D1' for group $12 is not representable in strict YARA lowering")
                && value.contains("ndb signed jump")
                && value.contains("macro-group `$12$` semantics depend on CLI_OFF_MACRO")
    )));
}

#[test]
fn lowers_macro_subsignature_with_mixed_linked_ndb_members_ignores_bad_and_keeps_good() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:0:$12:AA{-15}BB").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:626262").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert!(rule
        .strings
        .iter()
        .any(|s| matches!(s, YaraString::Raw(raw) if raw == "$m1_0 = { 62 62 62 }")));
    assert!(rule.condition.contains("for any j in (1..#m1_0)"));
    assert!(!rule.condition.contains("and false"));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("ndb macro link 'D1' for group $12 is not representable in strict YARA lowering")
                && value.contains("ndb signed jump")
                && value.contains("macro-group `$12$` resolved via linked ndb members [D2]")
    )));
}

#[test]
fn lowers_macro_subsignature_to_false_when_all_linked_ndb_members_are_ignored() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:8:$12:626262").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:AA{-15}BB").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();

    assert_eq!(rule.condition, "($s0 and false)");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("target_type=8 (expected 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, or 12)")
                && value.contains("ndb macro link 'D2' for group $12 is not representable in strict YARA lowering")
                && value.contains("ndb signed jump")
                && value.contains("macro-group `$12$` semantics depend on CLI_OFF_MACRO")
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
            if key == "clamav_unsupported" && value == "fuzzy_img_hash_runtime_match"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes" && value.contains("fuzzy_img")
    )));
}

#[test]
fn lowers_malformed_fuzzy_img_to_safe_false_instead_of_raw_string() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#zzzzzzzzzzzzzzzz#0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "fuzzy_img_hash_runtime_match"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img format unsupported/invalid")
    )));
}

#[test]
fn lowers_fuzzy_img_short_hash_to_safe_false_with_hash_length_note() {
    // ClamAV reference: unit_tests/clamscan/fuzzy_img_hash_test.py:92-105
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#abcdef#0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img format unsupported/invalid")
                && value.contains("hash must be exactly 16 hex chars")
    )));
}

#[test]
fn lowers_fuzzy_img_invalid_distance_token_to_safe_false() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#x").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img format unsupported/invalid")
                && value.contains("distance 'x' is not a valid unsigned integer")
    )));
}

#[test]
fn lowers_fuzzy_img_with_too_many_separators_to_safe_false() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#0#1").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img format unsupported/invalid")
                && value.contains("too many '#' separators")
    )));
}

#[test]
fn lowers_fuzzy_img_with_missing_hash_to_safe_false() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img##0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.strings.is_empty());
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("fuzzy_img format unsupported/invalid")
                && value.contains("hash must be exactly 16 hex chars")
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
fn lowers_ndb_square_right_flank_structure_when_representable() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2767-2836 (`[]` allows core `[n-m]` single-byte-right-flank form)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AABB[1-2]CC").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("$a = { AA BB [1-2] CC }"));
    assert_eq!(rule.condition, "$a");
}

#[test]
fn lowers_ndb_square_dual_flank_structure_when_representable() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2767-2836 (each `[]` must bind to a single-byte flank while leaving a core)
    // - libclamav/matcher-ac.c:1286-1304,1365-1381 (`ch[0]`/`ch[1]` enforce left/right distance checks around core)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[1-2]BBCC[3-4]DD").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("$a = { AA [1-2] BB CC [3-4] DD }"));
    assert_eq!(rule.condition, "$a");
}

#[test]
fn rejects_ndb_square_jump_without_single_byte_flank_for_strictness() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2767-2836 (invalid when neither side of `[]` is a single-byte flank)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AABB[1-2]CCDD").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("[] jump positional structure")
                && value.contains("single-byte flank")
                && value.contains("strict lowering")
    )));
}

#[test]
fn rejects_ndb_square_jump_with_more_than_two_constraints_for_strictness() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2768-2838 (`for (i = 0; i < 2; i++)` limits processing to at most 2 square-jump constraints)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[1]BB[2]CC[3]DD").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("more than 2 [] jumps")
                && value.contains("strict lowering")
    )));
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

#[test]
fn lowers_idb_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: LogicalSignatures.md (`ICONNAME:GROUP1:GROUP2:ICON_HASH`)
    // - source: libclamav/readdb.c:1365-1376,1388-1397 (`ICO_TOKENS=4`, hash len=124, size=16/24/32)
    let icon_hash = format!("10{}", "0".repeat(122));
    let raw = format!("Icon.Sample-1:IEXPLORE:GENERIC:{icon_hash}");
    let sig = IdbSignature::parse(raw.as_str()).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.name, "Icon_Sample_1");
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "idb_icon_fuzzy_match"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("icon matcher")
                && value.contains("IconGroup")
    )));
}

#[test]
fn lowers_cbc_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/BytecodeSignatures (`.cbc` is ASCII-encoded executable bytecode)
    // - source: libclamav/readdb.c:2332-2439 (`cli_loadcbc` -> `cli_bytecode_load`, runtime hooks)
    let raw = "VIRUSNAME Bytecode.Sample\nFUNCTIONALITY_LEVEL_MIN 51";
    let sig = CbcSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("CBC_bytecode_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "cbc_bytecode_vm"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("bytecode VM")
                && value.contains("runtime hooks")
    )));
}

#[test]
fn lowers_cdb_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/ContainerMetadata.html (`VirusName:ContainerType:...:Res2[:MinFL[:MaxFL]]`)
    // - source: libclamav/readdb.c:3112-3137,3234-3244 (`CDB_TOKENS=12`, numeric/range fields, IsEncrypted `*|0|1`)
    let raw = "Container.Sample-1:CL_TYPE_ZIP:*:.*\\.exe:10-20:20-40:0:1:*:*:120:255";
    let sig = CdbSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.name, "Container_Sample_1");
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "cdb_container_metadata_match"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("container traversal")
                && value.contains("CRC")
    )));
}

#[test]
fn lowers_cfg_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*.cfg` is DB config metadata, not scan signature body)
    let raw = "DOCUMENT:0x5:11:13";
    let sig = CfgSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("CFG_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "cfg_runtime_configuration_metadata"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "clamav_cfg_domain" && value == "DOCUMENT"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("runtime configuration")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_crb_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/AuthenticodeRules.html (`Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;NotBefore;Comment[;minFL[;maxFL]]`)
    // - source: libclamav/readdb.c:3318-3322,3358,3389-3478 (`CRT_TOKENS=13`, token range 11..13, trust/usage flags, optional serial/not_before)
    let raw = "Trusted.Cert-1;1;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;A1B2C3D4;010001;1;0;1;0;baseline-comment;120;255";
    let sig = CrbSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.name, "Trusted_Cert_1");
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "crb_authenticode_cert_chain"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("certificate trust/revocation")
                && value.contains("verification/runtime trust store")
    )));
}

#[test]
fn lowers_pdb_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/PhishSigs.html (`R:DisplayedURL[:FuncLevelSpec]`, `H:DisplayedHostname[:FuncLevelSpec]`)
    // - source: libclamav/readdb.c:1613-1627 (`cli_loadpdb` -> `load_regex_matcher`)
    // - source: libclamav/regex_list.c:503-577 (`R/H` dispatch) and 355-395 (`:min-max` functionality-level parsing)
    let raw = "H:amazon.com:20-30";
    let sig = PdbSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("PDB_host_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "pdb_displayed_url_match"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("RealURL/DisplayedURL")
                && value.contains("phish_protected_domain")
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "min_flevel" && value == "20"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "max_flevel" && value == "30"
    )));
}

#[test]
fn lowers_wdb_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/PhishSigs.html (`X:RealURL:DisplayedURL[:FuncLevelSpec]`, `Y:RealURL[:FuncLevelSpec]`, `M:RealHostname:DisplayedHostname[:FuncLevelSpec]`)
    // - source: libclamav/readdb.c:1593-1610 (`cli_loadwdb` -> `load_regex_matcher(..., is_allow_list_lookup=1)`)
    // - source: libclamav/regex_list.c:503-519,568-576 (`X/Y/M` dispatch) and 355-395 (`:min-max` functionality-level parsing)
    let raw = "M:www\\.google\\.ro:www\\.google\\.com:20-30";
    let sig = WdbSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("WDB_host_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "wdb_allow_list_match"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("RealURL/DisplayedURL")
                && value.contains("allow-list")
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "min_flevel" && value == "20"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "max_flevel" && value == "30"
    )));
}

#[test]
fn lowers_ftm_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/FileTypeMagic (`magictype:offset:magicbytes:name:rtype:type[:min_flevel[:max_flevel]]`)
    // - source: libclamav/readdb.c:2468-2600 (`cli_loadftm`; `magictype` dispatch + filetype matcher wiring)
    let raw = "1:*:25504446:PDF-body:CL_TYPE_ANY:CL_TYPE_PDF:120:255";
    let sig = FtmSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("FTM_ac_pattern_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "ftm_file_type_magic"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_ftm_name" && value == "PDF-body"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("filetype engine integration")
                && value.contains("cli_ftcode")
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "min_flevel" && value == "120"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value } if key == "max_flevel" && value == "255"
    )));
}

#[test]
fn lowers_fp_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/AllowLists (`.fp` uses MD5 file hash allow-list entries)
    // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
    let raw = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
    let sig = FpSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("FP_Eicar_Test_Signature_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "fp_allow_list_override"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_fp_hash_type" && value == "md5"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("suppress detections")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_sfp_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/AllowLists (`.sfp` uses SHA1/SHA256 file hash allow-list entries)
    // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
    let raw = "0059ee2322c3301263c8006fd780d7fe95a30572:1705472:Example:120";
    let sig = SfpSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("SFP_sha1_Example_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "sfp_allow_list_override"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_sfp_hash_type" && value == "sha1"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "min_flevel" && value == "120"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("suppress detections")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_ign_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/AllowLists (`.ign2`: `SignatureName[:md5(entry)]`; `.ign` legacy-compatible)
    // - source: libclamav/readdb.c:2721-2821 (`cli_loadign` supports token count 1..3)
    let raw = "legacy-repo:legacy-id:Eicar-Test-Signature";
    let sig = IgnSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("IGN_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "ign_signature_ignore_list"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_ign_signature_name" && value == "Eicar-Test-Signature"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_ign_legacy_prefix_1" && value == "legacy-repo"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("ignore-lists suppress matching signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_ign2_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures/AllowLists (`.ign2`: `SignatureName[:md5(entry)]`)
    // - source: libclamav/readdb.c:2721-2821 (`cli_loadign` handles .ign and .ign2)
    let raw = "Eicar-Test-Signature:bc356bae4c42f19a3de16e333ba3569c";
    let sig = Ign2Signature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("IGN2_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "ign2_signature_ignore_list"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_ign2_md5" && value == "bc356bae4c42f19a3de16e333ba3569c"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("ignore-lists suppress matching signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_hdu_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
    // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
    let raw = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
    let sig = HduSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("HDU_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "hdu_pua_hash_signature_semantics"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_hdu_hash" && value == "44d88612fea8a8f36de82e1278abb02f"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("PUA-gated hash signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_hsu_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
    // - docs: manual/Signatures/HashSignatures (`HashString:FileSize:MalwareName[:MinFL]`)
    let raw =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature:73";
    let sig = HsuSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("HSU_sha256_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "hsu_pua_hash_signature_semantics"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_hsu_hash_type" && value == "sha256"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("PUA-gated hash signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_mdu_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
    // - docs: manual/Signatures/HashSignatures (`PESectionSize:Hash:MalwareName[:MinFL]`)
    let raw = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature:73";
    let sig = MduSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("MDU_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "mdu_pua_section_hash_signature_semantics"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_mdu_hash_type" && value == "md5"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("PUA-gated section-hash signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_msu_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
    // - docs: manual/Signatures/HashSignatures (`PESectionSize:Hash:MalwareName[:MinFL]`)
    let raw =
        "45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Eicar-Test-Signature:73";
    let sig = MsuSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("MSU_sha256_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "msu_pua_section_hash_signature_semantics"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_msu_hash_type" && value == "sha256"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("PUA-gated section-hash signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_ndu_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*u` DB extensions are loaded in PUA mode)
    // - docs: manual/Signatures (`*.ndb`/`*.ndu` use extended signature record format)
    let raw = "PUA.Win.Packer.YodaProt-1:1:EP+0:e803000000eb01??bb55000000e803000000eb01??e88e000000e803000000eb01??e881000000e803000000eb01??e8b7000000e803000000eb01??e8aa000000e803000000eb01??83fb55e803000000eb01??752d:18";
    let sig = NduSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("NDU_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "ndu_pua_extended_signature_semantics"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_target_type" && value == "1"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("PUA-gated extended signatures")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_info_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*.info` contains DB metadata/index info)
    let raw =
        "ClamAV-VDB:14 Feb 2026 07-25 +0000:27912:355104:90:X:X:svc.clamav-publisher:1771053920";
    let sig = InfoSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("INFO_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "info_db_metadata_record"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_info_record_type" && value == "ClamAV-VDB"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("metadata/signature index")
                && value.contains("lowered to false for safety")
    )));
}

#[test]
fn lowers_ldu_signature_to_strict_false_for_safety() {
    // ClamAV references:
    // - docs: manual/Signatures (`*.ldb *.ldu; *.idb: Logical Signatures`)
    // - docs: same page notes `*u` extensions are loaded in PUA mode
    let raw = "PUA.CVE_2012_0198;Engine:51-255,Target:3;0&1;636C6173;72756E";
    let sig = LduSignature::parse(raw).unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.name.starts_with("LDU_"));
    assert_eq!(rule.condition, "false");
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_unsupported" && value == "ldu_pua_logical_signature_semantics"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_ldu_signature_name" && value == "PUA.CVE_2012_0198"
    )));
    assert!(rule.meta.iter().any(|m| matches!(
        m,
        YaraMeta::Entry { key, value }
            if key == "clamav_lowering_notes"
                && value.contains("PUA-gated logical signatures")
                && value.contains("lowered to false for safety")
    )));
}
