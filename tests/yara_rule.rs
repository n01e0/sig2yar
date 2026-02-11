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
fn lowers_match_count_expression() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)=1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "1 of ($s0, $s1)");
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
fn lowers_byte_comparison_with_value_check() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>26#ib2#>512)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert!(rule.condition.contains("for any j in (1..#s0)"));
    assert!(rule.condition.contains("uint16be(@s0[j] + 26) > 512"));
    assert!(rule.condition.contains("(@s0[j] + 26) + 2 <= filesize"));
}

#[test]
fn byte_comparison_non_raw_falls_back_to_alias() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>26#db2#>512)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert_eq!(rule.condition, "($s0 and $s0)");
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("fell back to trigger alias"))));
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
fn lowers_fuzzy_img_as_literal_fallback() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.condition, "$s0");
    assert!(rule.strings.iter().any(|s| matches!(
        s,
        YaraString::Raw(raw) if raw == "$s0 = \"fuzzy_img#af2ad01ed42993c7#0\""
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
fn lowers_ndb_target_type_html_with_constraint() {
    let sig = NdbSignature::parse("Html.Test-1:3:*:3c68746d6c3e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint8(j) == 0x3C"));
    assert!(rule.condition.contains("for all i"));
    assert!(rule
        .meta
        .iter()
        .any(|m| matches!(m, YaraMeta::Entry { key, value } if key == "clamav_lowering_notes" && value.contains("target_type=3"))));
}

#[test]
fn lowers_ndb_target_type_mail_with_constraint() {
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert!(rule.condition.contains("uint32(0) == 0x6D6F7246"));
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

    assert!(rule.condition.contains("for all i"));
    assert!(rule.condition.contains("uint8(i) >= 0x20"));
}
