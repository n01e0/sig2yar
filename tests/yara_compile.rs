use sig2yar::parser::{logical::LogicalSignature, ndb::NdbSignature};
use sig2yar::yara::{self, YaraRule};

#[test]
fn yara_rule_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile generated rule");
}

#[test]
fn yara_rule_with_raw_and_pcre_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;hello::ia;0/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile raw/pcre generated rule");
}

#[test]
fn yara_rule_with_pcre_trigger_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300:0/abc/sme").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre-trigger-prefix generated rule");
}

#[test]
fn yara_rule_with_byte_macro_fuzzy_compiles_with_yara_x() {
    let sig = LogicalSignature::parse(
        "Foo.Bar-1;Target:1;0&1&2&3;41414141;0(>>26#ib2#>512);${6-7}0$;fuzzy_img#af2ad01ed42993c7#0",
    )
    .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile byte/macro/fuzzy generated rule");
}

#[test]
fn ndb_rule_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:41424344:73").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile generated ndb rule");
}

#[test]
fn ndb_rule_with_ep_offset_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:1:EP+0,15:83e0038935{4}893d{4}").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb EP-offset rule");
}

#[test]
fn ndb_rule_with_alternatives_and_wildcards_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:2e0064006c006c00??003a005c00(45|65)00")
        .unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb complex hex rule");
}

#[test]
fn ndb_rule_with_target_type_3_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Html.Test-1:3:*:3c68746d6c3e").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=3 rule");
}

#[test]
fn ndb_rule_with_target_type_7_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Txt.Test-1:7:*:68656c6c6f").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=7 rule");
}

#[test]
fn ndb_rule_with_open_ended_jump_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{10-}BB").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb open-ended jump rule");
}
