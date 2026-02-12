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
fn yara_rule_with_hex_nocase_modifier_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile hex-nocase generated rule");
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
fn yara_rule_with_pcre_range_without_e_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;200,300:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre-maxshift-without-e safety-false rule");
}

#[test]
fn yara_rule_with_pcre_flag_e_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/E").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-E safety-false rule");
}

#[test]
fn yara_rule_with_pcre_x_flag_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/a b c/x").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-x generated rule");
}

#[test]
fn yara_rule_with_pcre_u_flag_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/a.+b/U").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-U generated rule");
}

#[test]
fn yara_rule_with_target_description_constraints_compiles_with_yara_x() {
    let sig = LogicalSignature::parse(
        "Foo.Bar-1;Target:1,FileSize:10-20,EntryPoint:100-200,NumberOfSections:2-4;0;41414141",
    )
    .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile target-description constrained rule");
}

#[test]
fn yara_rule_with_target_description_container_constraint_compiles_with_yara_x() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1,Container:CL_TYPE_ZIP;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile target-description container constrained rule");
}

#[test]
fn yara_rule_with_target_description_intermediates_constraint_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1,Intermediates:1;0;41414141").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile target-description intermediates constrained rule");
}

#[test]
fn yara_rule_with_multithreshold_expression_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)>2,1;41414141;42424242").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile multithreshold generated rule");
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
fn yara_rule_with_non_raw_byte_comparison_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#he4#=1A2B)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile non-raw byte-compare rule");
}

#[test]
fn yara_rule_with_non_raw_byte_comparison_gt_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#de3#>12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile non-raw byte-compare GT rule");
}

#[test]
fn yara_rule_with_non_raw_byte_comparison_lt_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>2#he2#<A0)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile non-raw byte-compare LT rule");
}

#[test]
fn yara_rule_with_non_raw_byte_comparison_non_exact_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>26#db2#>512)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile non-raw byte-compare non-exact fallback(false) rule");
}

#[test]
fn yara_rule_with_raw_byte_comparison_variable_size_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#ib3#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile raw byte-compare variable-size rule");
}

#[test]
fn yara_rule_with_raw_byte_comparison_unsupported_size_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#ib9#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile raw byte-compare unsupported-size false rule");
}

#[test]
fn yara_rule_with_raw_byte_comparison_out_of_range_threshold_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>2#ib1#<300)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile raw byte-compare out-of-range-threshold false rule");
}

#[test]
fn yara_rule_with_byte_comparison_contradictory_clauses_false_compiles_with_yara_x() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>2#ib2#>512,<100)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile byte-compare contradictory-clause false rule");
}

#[test]
fn ndb_rule_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:41424344:73").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile generated ndb rule");
}

#[test]
fn ndb_rule_with_descending_absolute_offset_range_fallback_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:100,10:41424344").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile ndb descending absolute-range fallback rule");
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

#[test]
fn ndb_rule_with_descending_positive_range_jump_fallback_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{10-5}BB").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile ndb descending-range fallback rule");
}

#[test]
fn ndb_rule_with_complex_signed_range_jump_fallback_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{-10-5}BB").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb signed-range fallback rule");
}

#[test]
fn ndb_rule_with_target_type_8_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Unknown.Test-1:8:*:41424344").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=8 rule");
}

#[test]
fn ndb_rule_with_target_type_13_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Unknown.Test-2:13:*:41424344").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=13 rule");
}
