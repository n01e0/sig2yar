use sig2yar::parser::logical::LogicalSignature;
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
fn lowers_byte_comparison_as_trigger_alias() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>26#ib2#>512)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert_eq!(rule.condition, "($s0 and $s0)");
}

#[test]
fn lowers_macro_subsignature_as_reference_alias() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();

    assert_eq!(rule.strings.len(), 1);
    assert_eq!(rule.condition, "($s0 or $s0)");
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
