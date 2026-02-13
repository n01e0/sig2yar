use sig2yar::parser::{logical::LogicalSignature, ndb::NdbSignature};
use sig2yar::yara::{self, YaraRule};

fn scan_match_count(src: &str, data: &[u8]) -> usize {
    let rules = yara_x::compile(src).expect("yara-x failed to compile rule for scan");
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .expect("yara-x failed to scan data for rule");
    results.matching_rules().len()
}

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
fn yara_rule_with_pcre_trigger_prefix_resolved_false_rejects_scan_for_safety() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;9/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    let data = b"abc";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn yara_rule_with_exact_pcre_offset_compiles_with_yara_x_from_clamav_regex_fixture() {
    // ClamAV reference: unit_tests/clamscan/regex_test.py:127-129,152-174
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;68656c6c6f20;5:0/hello blee/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre exact-offset generated rule");
}

#[test]
fn yara_rule_with_exact_pcre_offset_match_fixture_compiles_with_yara_x() {
    // ClamAV reference: unit_tests/clamscan/regex_test.py:170-183
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;68656c6c6f20;5:0/llo blee/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre exact-offset match-fixture rule");
}

#[test]
fn yara_rule_with_re_range_offset_compiles_with_yara_x_from_clamav_matcher_fixture() {
    // ClamAV reference: unit_tests/check_matchers.c:146-149,497-503 (pcre_testdata expected_result)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,6:0/atre/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre range+re generated rule");
}

#[test]
fn yara_rule_with_re_range_offset_nonmatch_fixture_compiles_with_yara_x() {
    // ClamAV reference: unit_tests/check_matchers.c:146-149,497-503 (Test8 `/apie/re` expected CL_SUCCESS)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,2:0/apie/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre range+re nonmatch-fixture generated rule");
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
fn yara_rule_with_pcre_ep_plus_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP+10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre EP+ offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_ep_minus_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP-4:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre EP- offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_star_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre '*' offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_section_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S2+4,8:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre Sx+ offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_section_end_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre SE offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_last_section_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SL+16:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre SL+ offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_eof_minus_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre EOF- offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_versioninfo_offset_prefix_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;VI:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre VI offset-prefix safety-false rule");
}

#[test]
fn yara_rule_with_pcre_non_numeric_offset_prefix_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP+foo:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre non-numeric offset-prefix safety-false rule");
}

#[test]
fn yara_rule_with_pcre_macro_group_offset_prefix_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$1$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre macro-group offset-prefix safety-false rule");
}

#[test]
fn yara_rule_with_pcre_flag_e_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/E").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-E safety-false rule");
}

#[test]
fn yara_rule_with_pcre_unsupported_flag_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/d").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre-unsupported-flag safety-false rule");
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
fn yara_rule_with_macro_group_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile macro-group safety-false rule");
}

#[test]
fn yara_rule_with_descending_macro_range_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${7-6}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile descending-macro-range safety-false rule");
}

#[test]
fn yara_rule_with_invalid_macro_format_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6}0$").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile invalid-macro-format safety-false rule");
}

#[test]
fn yara_rule_with_fuzzy_img_second_subsig_false_compiles_with_yara_x_from_clamav_fixture() {
    // ClamAV reference: unit_tests/clamscan/fuzzy_img_hash_test.py:40-42,54-61
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;49484452;fuzzy_img#af2ad01ed42993c7#0")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile fuzzy_img second-subsig safety-false rule");
}

#[test]
fn yara_rule_with_fuzzy_img_nonzero_distance_false_compiles_with_yara_x_from_clamav_fixture() {
    // ClamAV reference: unit_tests/clamscan/fuzzy_img_hash_test.py:116-132
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#1").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile fuzzy_img nonzero-distance safety-false rule");
}

#[test]
fn yara_rule_with_non_raw_byte_comparison_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#he4#=1A2B)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile non-raw byte-compare rule");
}

#[test]
fn yara_rule_with_non_raw_hex_numeric_threshold_matches_hex_digit_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3130;0(>>0#he2#=10)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    let data = b"xx10yy";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn yara_rule_with_non_raw_hex_numeric_threshold_rejects_decimal_interpretation_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3041;0(>>0#he2#=10)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    let data = b"xx0Ayy";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn yara_rule_with_non_raw_byte_comparison_gt_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#de3#>12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile non-raw byte-compare GT rule");
}

#[test]
fn yara_rule_with_non_raw_decimal_hex_alpha_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#de3#>A0)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile non-raw decimal-hex-alpha safety-false rule");
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
fn yara_rule_with_invalid_byte_comparison_format_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#he2#=1G)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    let data = b"AAAA0(>>4#he2#=1G)";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
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
fn ndb_rule_with_absolute_range_offset_boundary_matches_representable_fixture() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:1,1:4142").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"XABY";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn ndb_rule_with_absolute_range_offset_boundary_rejects_nonmatch_fixture() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:1,1:4142").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"ABXY";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_malformed_absolute_offset_range_strict_false_rejects_scan() {
    // ClamAV reference: libclamav/matcher.c:365-381 (`cli_caloff` allows only numeric `n[,maxshift]`).
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:1,:4142").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"XABY";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_ep_offset_without_sign_strict_false_rejects_scan() {
    // ClamAV reference: libclamav/matcher.c:384-395 (`cli_caloff` accepts `EP+<num>` / `EP-<num>` only).
    let sig = NdbSignature::parse("Win.Trojan.Example-1:1:EP10:41424344").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"ABCD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_eof_plus_offset_strict_false_rejects_scan() {
    // ClamAV reference: libclamav/matcher.c:422-428 (`cli_caloff` accepts `EOF-<num>` only).
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:EOF+10:41424344").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"ABCD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_relative_offset_on_generic_target_strict_false_rejects_scan() {
    // ClamAV reference:
    // - libclamav/matcher.c:453-457 (`cli_caloff`: EP/Sx/SE/SL require PE/ELF/Mach-O target)
    // - libclamav/matcher.h:205-213 (`TARGET_GENERIC=0`; executable targets are 1/6/9)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:EP+10:41424344").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"ABCD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
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
fn ndb_rule_with_target_type_3_matches_valid_html_boundaries() {
    // ClamAV reference:
    // - libclamav/scanners.c:2563-2589 (normalized HTML buffers are scanned with CL_TYPE_HTML)
    // - libclamav/htmlnorm.c:962-1000 (tag token ends on `>` or whitespace)
    // - libclamav/htmlnorm.c:1229-1249 (exact closing tag token handling)
    let sig = NdbSignature::parse("Html.Test-1:3:*:3c68746d6c3e").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"<html><body>ok</body></html>";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn ndb_rule_with_target_type_3_rejects_close_tag_without_terminator() {
    // Strict-side non-match case: `</htmlx>` must not satisfy close-tag marker checks.
    // ClamAV HTML tokenizer parses exact tag names and boundaries (htmlnorm.c state machine).
    let sig = NdbSignature::parse("Html.Test-1:3:*:3c68746d6c3e").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"<html>ok</htmlx>";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_target_type_4_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=4 rule");
}

#[test]
fn ndb_rule_with_target_type_4_matches_line_start_header_before_separator() {
    // ClamAV reference:
    // - libclamav/mbox.c:1173-1183 (blank line marks end-of-header/start-of-body)
    // - libclamav/mbox.c:1263-1268,1330-1391 (header lines parsed before body as header entries)
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"From: sender@example.com\r\nSubject: hello\r\nDate: Thu, 12 Feb 2026 21:42:00 +0900\r\n\r\nbody";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn ndb_rule_with_target_type_4_rejects_secondary_header_not_at_line_start() {
    // Strict-side non-match case: header token inside a line (`X-Subject:`) must not be treated
    // as a canonical header line before separator.
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"From: sender@example.com\r\nX-Subject: hello\r\n\r\nbody";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_target_type_4_rejects_secondary_header_after_separator() {
    // Strict-side non-match case: canonical header appearing only after header/body separator
    // must not satisfy pre-separator header constraints.
    let sig = NdbSignature::parse("Mail.Test-1:4:*:46726f6d3a").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"From: sender@example.com\r\n\r\nSubject: hello\r\nbody";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_target_type_7_compiles_with_yara_x() {
    // ClamAV reference:
    // - libclamav/textnorm.c:64-68 (text normalization contract)
    // - libclamav/textnorm.c:74-82,115-129 (uppercase A-Z normalized to lowercase)
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
fn ndb_rule_with_square_range_jump_matches_representable_fixture() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2751-2786 (`[n]` / `[n-m]` accepted only as ascending ranges)
    // - libclamav/matcher-ac.h:32 (`AC_CH_MAXDIST` == 32)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[2-4]BB").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\x01\x02\xBB";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn ndb_rule_with_square_range_jump_rejects_nonmatch_fixture() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[2-4]BB").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\x01\xBB";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_square_right_flank_structure_matches_representable_fixture() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2767-2836 (`[]` allows core `[n-m]` single-byte-right-flank form)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AABB[1-2]CC").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\xBB\x01\xCC";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn ndb_rule_with_square_right_flank_structure_rejects_nonmatch_fixture() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AABB[1-2]CC").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\xBB\x01\x02\x03\xCC";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_square_dual_flank_structure_matches_representable_fixture() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2767-2836 (`[]` parsing requires single-byte flank/core structure)
    // - libclamav/matcher-ac.c:1286-1304,1365-1381 (`ch[0]`/`ch[1]` left/right distance checks)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[1-2]BBCC[3-4]DD").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\x01\xBB\xCC\x01\x02\x03\xDD";
    assert_eq!(scan_match_count(src.as_str(), data), 1);
}

#[test]
fn ndb_rule_with_square_dual_flank_structure_rejects_nonmatch_fixture() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[1-2]BBCC[3-4]DD").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\x01\xBB\xCC\x01\x02\xDD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_square_jump_without_single_byte_flank_strict_false_rejects_scan() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2767-2836 (invalid when neither `[]` side is a single-byte flank)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AABB[1-2]CCDD").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\xBB\x01\xCC\xDD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_more_than_two_square_jumps_strict_false_rejects_scan() {
    // ClamAV reference:
    // - libclamav/matcher-ac.c:2768-2838 (`for (i = 0; i < 2; i++)`)
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[1]BB[2]CC[3]DD").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"\xAA\x00\xBB\x00\x00\xCC\x00\x00\x00\xDD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_descending_positive_range_jump_strict_false_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{10-5}BB").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile ndb descending-range strict-false rule");
}

#[test]
fn ndb_rule_with_complex_signed_range_jump_strict_false_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{-10-5}BB").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile ndb signed-range strict-false rule");
}

#[test]
fn ndb_rule_with_signed_negative_jump_strict_false_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA{-15}BB").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile ndb signed-negative-jump strict-false rule");
}

#[test]
fn ndb_rule_with_square_open_or_signed_bounds_strict_false_compiles_with_yara_x() {
    let sig = NdbSignature::parse("Win.Trojan.Example-1:0:*:AA[-5]BB").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile ndb square-open-bounds strict-false rule");
}

#[test]
fn ndb_rule_with_target_type_8_compiles_with_yara_x() {
    // ClamAV reference: libclamav/matcher.h:205-219 (`TARGET_NOT_USED = 8`).
    let sig = NdbSignature::parse("Unknown.Test-1:8:*:41424344").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=8 rule");
}

#[test]
fn ndb_rule_with_target_type_13_compiles_with_yara_x() {
    // ClamAV reference: libclamav/matcher.h:218-219 (`TARGET_INTERNAL = 13`, `TARGET_OTHER = 14`).
    let sig = NdbSignature::parse("Unknown.Test-2:13:*:41424344").unwrap();
    let ir = sig.to_ir();
    let src = yara::render_ndb_signature(&ir);

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndb target_type=13 rule");
}

#[test]
fn ndb_rule_with_target_type_14_strict_false_rejects_scan() {
    let sig = NdbSignature::parse("Unknown.Test-3:14:*:41424344").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"ABCD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn ndb_rule_with_non_numeric_target_type_strict_false_rejects_scan() {
    // ClamAV reference: libclamav/readdb.c:1714-1716 (target must be `*` or numeric).
    let sig = NdbSignature::parse("Unknown.Test-4:foo:*:41424344").unwrap();
    let src = yara::render_ndb_signature(&sig.to_ir());

    let data = b"ABCD";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}
