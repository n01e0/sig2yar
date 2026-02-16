use sig2yar::parser::{
    cbc::CbcSignature, cdb::CdbSignature, cfg::CfgSignature, crb::CrbSignature, fp::FpSignature,
    ftm::FtmSignature, hdu::HduSignature, hsu::HsuSignature, idb::IdbSignature, ign::IgnSignature,
    ign2::Ign2Signature, info::InfoSignature, ldu::LduSignature, logical::LogicalSignature,
    mdu::MduSignature, msu::MsuSignature, ndb::NdbSignature, ndu::NduSignature, pdb::PdbSignature,
    sfp::SfpSignature, wdb::WdbSignature,
};
use sig2yar::yara::{self, YaraRule};

fn scan_match_count(src: &str, data: &[u8]) -> usize {
    let rules = yara_x::compile(src).expect("yara-x failed to compile rule for scan");
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .expect("yara-x failed to scan data for rule");
    results.matching_rules().len()
}

fn pe_two_sections_fixture_with_aaaa_and_abc_in_section1() -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    let mut data = vec![0u8; 0x800];

    data[0..2].copy_from_slice(b"MZ");
    put_u32(&mut data, 0x3c, 0x80); // e_lfanew

    let nt = 0x80usize;
    data[nt..nt + 4].copy_from_slice(b"PE\0\0");

    let file_hdr = nt + 4;
    put_u16(&mut data, file_hdr, 0x014c); // IMAGE_FILE_MACHINE_I386
    put_u16(&mut data, file_hdr + 2, 2); // NumberOfSections
    put_u16(&mut data, file_hdr + 16, 0x00E0); // SizeOfOptionalHeader
    put_u16(&mut data, file_hdr + 18, 0x010F); // Characteristics

    let opt = file_hdr + 20;
    put_u16(&mut data, opt, 0x010b); // PE32
    put_u32(&mut data, opt + 16, 0x200); // AddressOfEntryPoint (RVA)
    put_u32(&mut data, opt + 28, 0x0040_0000); // ImageBase
    put_u32(&mut data, opt + 32, 0x1000); // SectionAlignment
    put_u32(&mut data, opt + 36, 0x200); // FileAlignment
    put_u32(&mut data, opt + 56, 0x3000); // SizeOfImage
    put_u32(&mut data, opt + 60, 0x200); // SizeOfHeaders
    put_u32(&mut data, opt + 92, 16); // NumberOfRvaAndSizes

    let sec = opt + 0xE0;

    // section 0: raw [0x200, 0x3ff]
    data[sec..sec + 8].copy_from_slice(b".s0\0\0\0\0\0");
    put_u32(&mut data, sec + 8, 0x200); // VirtualSize
    put_u32(&mut data, sec + 12, 0x1000); // VirtualAddress
    put_u32(&mut data, sec + 16, 0x200); // SizeOfRawData
    put_u32(&mut data, sec + 20, 0x200); // PointerToRawData
    put_u32(&mut data, sec + 36, 0x6000_0020); // Characteristics

    // section 1: raw [0x400, 0x5ff]
    let sec1 = sec + 40;
    data[sec1..sec1 + 8].copy_from_slice(b".s1\0\0\0\0\0");
    put_u32(&mut data, sec1 + 8, 0x200); // VirtualSize
    put_u32(&mut data, sec1 + 12, 0x2000); // VirtualAddress
    put_u32(&mut data, sec1 + 16, 0x200); // SizeOfRawData
    put_u32(&mut data, sec1 + 20, 0x400); // PointerToRawData
    put_u32(&mut data, sec1 + 36, 0x6000_0020); // Characteristics

    // Trigger subsig fixture (`41414141`) and section-1 payload (`abc` at 0x404)
    data[0x200..0x204].copy_from_slice(b"AAAA");
    data[0x404..0x407].copy_from_slice(b"abc");

    data
}

#[test]
fn pe_fixture_is_recognized_as_pe_for_offset_tests() {
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    let src = r#"
import "pe"
rule PEFixtureIsPE {
    condition:
        pe.is_pe
}
"#;

    assert_eq!(scan_match_count(src, &data), 1);
}

#[test]
fn pe_fixture_exposes_expected_section_metadata_for_offset_tests() {
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    let src = r#"
import "pe"
rule PEFixtureSanity {
    condition:
        pe.number_of_sections == 2 and
        pe.sections[0].raw_data_offset == 0x200 and
        pe.sections[1].raw_data_offset == 0x400
}
"#;

    assert_eq!(scan_match_count(src, &data), 1);
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
fn yara_rule_with_hex_wide_modifier_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::w").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile hex-wide generated rule");
}

#[test]
fn yara_rule_with_hex_wide_ascii_modifier_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::wa").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile hex-wide-ascii generated rule");
}

#[test]
fn yara_rule_with_hex_wide_modifier_matches_only_wide_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::w").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"A\x00B\x00C\x00"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"ABC"), 0);
}

#[test]
fn yara_rule_with_hex_wide_ascii_modifier_matches_ascii_and_wide_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;414243::wa").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"ABC"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"A\x00B\x00C\x00"), 1);
}

#[test]
fn yara_rule_with_hex_fullword_modifier_matches_with_non_alnum_boundaries() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;68656c6c6f::f").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("hex modifier 'f' lowered with strict non-alphanumeric boundary checks"));
    assert_eq!(scan_match_count(src.as_str(), b"hello"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"xhello"), 0);
    assert_eq!(scan_match_count(src.as_str(), b"hello1"), 0);
    assert_eq!(scan_match_count(src.as_str(), b"_hello_"), 1);
}

#[test]
fn yara_rule_with_hex_wide_fullword_modifier_matches_with_wide_boundaries() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;68656c6c6f::wf").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("hex modifier 'f' lowered with strict wide alnum+NUL boundary checks"));
    assert_eq!(
        scan_match_count(src.as_str(), b"h\x00e\x00l\x00l\x00o\x00"),
        1
    );
    assert_eq!(
        scan_match_count(src.as_str(), b"x\x00h\x00e\x00l\x00l\x00o\x00"),
        0
    );
    assert_eq!(
        scan_match_count(src.as_str(), b"h\x00e\x00l\x00l\x00o\x00y\x00"),
        0
    );
    assert_eq!(
        scan_match_count(src.as_str(), b"_\x00h\x00e\x00l\x00l\x00o\x00_\x00"),
        1
    );
}

#[test]
fn yara_rule_with_hex_wide_ascii_fullword_modifier_matches_ascii_and_wide_boundaries() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;68656c6c6f::waf").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains(
        "hex modifier 'f' lowered with strict ascii|wide branch-dispatched boundary checks"
    ));
    assert_eq!(scan_match_count(src.as_str(), b"hello"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"xhello"), 0);
    assert_eq!(scan_match_count(src.as_str(), b"hello1"), 0);
    assert_eq!(
        scan_match_count(src.as_str(), b"h\x00e\x00l\x00l\x00o\x00"),
        1
    );
    assert_eq!(
        scan_match_count(src.as_str(), b"x\x00h\x00e\x00l\x00l\x00o\x00"),
        0
    );
    assert_eq!(
        scan_match_count(src.as_str(), b"h\x00e\x00l\x00l\x00o\x00y\x00"),
        0
    );
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
fn yara_rule_with_pcre_trigger_prefix_missing_trigger_expression_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;200,300:/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre trigger prefix parse failed"));
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_trigger_prefix_malformed_expression_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;200,300:foo/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("lowered to false for safety"));
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_trigger_prefix_mixed_missing_reference_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;0|9/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("references unsupported/missing subsig index(es) 9"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_malformed_pcre_subsignature_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre subsignature format unsupported/invalid"));
    assert_eq!(scan_match_count(src.as_str(), b"xx0/abcxx"), 0);
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
fn yara_rule_with_pcre_exact_offset_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/r").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'r' with exact offset prefix"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_exact_offset_with_encompass_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'e' with exact offset prefix"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzabc"), 0);
}

#[test]
fn yara_rule_with_re_range_offset_false_rejects_scan() {
    // ClamAV reference: unit_tests/check_matchers.c:146-149,497-503 (pcre_testdata expected_result)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,6:0/atre/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAxxatre"), 0);
}

#[test]
fn yara_rule_with_re_range_offset_nonmatch_fixture_false_rejects_scan() {
    // ClamAV reference: unit_tests/check_matchers.c:146-149,497-503 (Test8 `/apie/re` expected CL_SUCCESS)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;2,2:0/apie/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAxxapie"), 0);
}

#[test]
fn yara_rule_with_pcre_encompass_match_end_boundary_nonmatch_fixture_rejects_scan() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:144 (Test7 `/34567890/e` with `3,7` expected CL_SUCCESS)
    // - matcher-pcre.c:624-629 (`e` uses bounded adjlength=adjshift)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;6E6F74;3,7:0/34567890/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("(@s1[j] + !s1[j]) <= 10"));
    assert_eq!(scan_match_count(src.as_str(), b"not34567890truly"), 0);
}

#[test]
fn yara_rule_with_pcre_encompass_match_end_boundary_match_fixture_matches_scan() {
    // ClamAV reference:
    // - unit_tests/check_matchers.c:142 (Test5 `/12345678/e` with `3,8` expected CL_VIRUS)
    // - matcher-pcre.c:624-629 (`e` uses bounded adjlength=adjshift)
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;6E6F74;3,8:0/12345678/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("(@s1[j] + !s1[j]) <= 11"));
    assert_eq!(scan_match_count(src.as_str(), b"not12345678truly"), 1);
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
fn yara_rule_with_pcre_ep_plus_offset_prefix_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP+10,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_ep_minus_offset_prefix_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EP-10,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_ep_offset_prefix_on_non_exec_target_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;EP+10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre offset prefix 'EP+/-' is invalid for target_type=any"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_section_offset_prefix_on_non_exec_target_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;S2+4,8:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre offset prefix 'Sx+' is invalid for target_type=any"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_last_section_offset_prefix_on_non_exec_target_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;SL+16:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre offset prefix 'SL+' is invalid for target_type=any"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_section_entire_offset_prefix_on_non_exec_target_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:0;1;41414141;SE1,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre offset prefix 'SE' is invalid for target_type=any"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_anchored_offset_prefix_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;10:0/abc/A").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile anchored-offset-prefix safety-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_anchored_with_rolling_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/Ar").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile anchored-with-rolling safety-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_anchored_flag_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/A").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile anchored safety-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_star_offset_prefix_with_re_flags_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag(s) 'r', 'e' on '*' offset prefix"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_star_with_maxshift_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;*,10:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("pcre offset prefix '*,10' unsupported"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_section_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S2+4,8:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre Sx+ offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_section_offset_prefix_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S1+4,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), &data), 0);
}

#[test]
fn yara_rule_with_pcre_section_end_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre SE offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_section_end_offset_prefix_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1,4:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), &data), 0);
}

#[test]
fn yara_rule_with_pcre_section_offset_prefix_valid_section_index_matches_pe_fixture() {
    // ClamAV reference: matcher.c recalculates Sx+ against sections[n].raw.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S1+4:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert_eq!(scan_match_count(src.as_str(), &data), 1);
}

#[test]
fn yara_rule_with_pcre_section_offset_prefix_out_of_range_section_rejects_pe_fixture() {
    // ClamAV reference: matcher.c sets CLI_OFF_NONE when section index is out-of-range.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;S2+4:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert_eq!(scan_match_count(src.as_str(), &data), 0);
}

#[test]
fn yara_rule_with_pcre_section_end_offset_prefix_valid_section_index_matches_pe_fixture() {
    // ClamAV reference: matcher.c/matcher-pcre.c uses section raw start + size (+maxshift) window for SE.
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE1,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert_eq!(scan_match_count(src.as_str(), &data), 1);
}

#[test]
fn yara_rule_with_pcre_section_end_offset_prefix_out_of_range_section_rejects_pe_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SE2,4:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert_eq!(scan_match_count(src.as_str(), &data), 0);
}

#[test]
fn yara_rule_with_pcre_last_section_offset_prefix_matches_last_section_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SL+4:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert_eq!(scan_match_count(src.as_str(), &data), 1);
}

#[test]
fn yara_rule_with_pcre_last_section_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SL+16:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre SL+ offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_last_section_offset_prefix_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;SL+4,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();
    let data = pe_two_sections_fixture_with_aaaa_and_abc_in_section1();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), &data), 0);
}

#[test]
fn yara_rule_with_pcre_eof_minus_offset_prefix_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-10:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre EOF- offset-prefix rule");
}

#[test]
fn yara_rule_with_pcre_eof_minus_offset_prefix_with_rolling_flag_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-10,8:0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag 'r' with maxshift"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_eof_minus_encompass_window_nonmatch_fixture_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-5,3:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("(@s1[j] + !s1[j]) <= filesize - 5 + 3"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAxxabc"), 0);
}

#[test]
fn yara_rule_with_pcre_eof_minus_encompass_window_match_fixture_matches_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;EOF-5,5:0/abc/e").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("(@s1[j] + !s1[j]) <= filesize - 5 + 5"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAxxabc"), 1);
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
fn yara_rule_with_pcre_versioninfo_prefixed_payload_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;VIjunk:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile pcre VIpayload offset-prefix safety-false rule");
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
fn yara_rule_with_pcre_invalid_macro_group_offset_prefix_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;1;41414141;$foo$:0/abc/").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect(
        "yara-x failed to compile malformed pcre macro-group offset-prefix safety-false rule",
    );
}

#[test]
fn yara_rule_with_pcre_flag_e_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/E").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-E safety-false rule");
}

#[test]
fn yara_rule_with_pcre_global_flag_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/g").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-g safety-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_legacy_a_flag_false_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/a").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-a safety-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
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
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/a b c/x").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-x generated rule");
}

#[test]
fn yara_rule_with_pcre_u_flag_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/a.+b/U").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pcre-U generated rule");
}

#[test]
fn yara_rule_with_pcre_self_referential_trigger_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;0/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("self-referential"));
    assert_eq!(scan_match_count(src.as_str(), b"abc"), 0);
}

#[test]
fn yara_rule_with_pcre_mixed_self_referential_trigger_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0|1/abc/i").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("self-referential"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
}

#[test]
fn yara_rule_with_pcre_count_trigger_prefix_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)=1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("count/distinct operators unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAABBBBzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_match_range_trigger_prefix_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)=1,2/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("count/distinct operators unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAABBBBzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_multi_gt_trigger_prefix_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)>1,1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("count/distinct operators unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAABBBBzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_multi_lt_trigger_prefix_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)<2,1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("count/distinct operators unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAABBBBzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_gt_trigger_prefix_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)>1/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("count/distinct operators unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAABBBBzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_lt_trigger_prefix_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;2;41414141;42424242;200,300:(0|1)<2/abc/")
            .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("count/distinct operators unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAABBBBzzzzabc"), 0);
}

#[test]
fn yara_rule_with_pcre_re_flags_without_offset_prefix_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0/abc/re").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("flag(s) 'r', 'e' require explicit offset/maxshift runtime semantics"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAabc"), 0);
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
fn yara_rule_with_multigt_single_subsig_distinct_ignored_matches_by_occurrence_count() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0>2,2;4142").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("multi-gt distinct threshold 2 ignored for single-subsig expression"));
    assert_eq!(scan_match_count(src.as_str(), b"ABxxAByyAB"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"ABxxAB"), 0);
}

#[test]
fn yara_rule_with_multilt_single_subsig_distinct_ignored_matches_by_occurrence_count() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0<3,2;4142").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("multi-lt distinct threshold 2 ignored for single-subsig expression"));
    assert_eq!(scan_match_count(src.as_str(), b"ABxxAB"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"ABxxAByyAB"), 0);
}

#[test]
fn yara_rule_with_multilt_group_incompatible_distinct_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;(0|1)<3,3;4142;4344").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("multi-lt distinct threshold 3 is incompatible with <3"));
    assert_eq!(scan_match_count(src.as_str(), b"ABxxCD"), 0);
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
fn yara_rule_with_macro_missing_trailing_dollar_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0|1;41414141;${6-7}0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("macro subsignature format unsupported/invalid"));
    assert_eq!(scan_match_count(src.as_str(), b"xx${6-7}0yy"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_members_compiles_with_yara_x() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:0:$12:626262").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:636363").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    yara_x::compile(src.as_str())
        .expect("yara-x failed to compile macro-group linked-ndb strict subset rule");
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_members_matches_and_rejects_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:0:$12:626262").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:636363").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"aaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_1_matches_with_mz_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:1:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint16(0) == 0x5A4D"));
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"ZZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_2_matches_with_ole2_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:2:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1"));
    assert_eq!(
        scan_match_count(src.as_str(), b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1aaaxxxbbb"),
        1
    );
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_3_matches_with_html_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:3:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("for any j in (0..filesize-1) : (uint8(j) == 0x3C)"));
    assert_eq!(
        scan_match_count(src.as_str(), b"<html><body>aaaxxxbbb</body></html>"),
        1
    );
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_4_matches_with_mail_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:4:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("for any s in (0..filesize-1)"));
    assert_eq!(
        scan_match_count(src.as_str(), b"From: a@b\nSubject: x\n\naaaxxxbbb"),
        1
    );
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_5_matches_with_graphics_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:5:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint32(0) == 0x474E5089"));
    assert_eq!(scan_match_count(src.as_str(), b"\x89PNGaaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_6_matches_with_elf_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:6:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint32(0) == 0x464C457F"));
    assert_eq!(scan_match_count(src.as_str(), b"\x7FELFaaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_7_matches_with_ascii_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:7:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("for all i in (0..filesize-1)"));
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"aaa\x01xxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_9_matches_with_macho_fat_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:9:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint32(0) == 0xCEFAEDFE"));
    assert!(src.contains("uint32(0) == 0xCAFEBABE"));
    assert_eq!(
        scan_match_count(src.as_str(), b"\xCA\xFE\xBA\xBEaaaxxxbbb"),
        1
    );
    assert_eq!(scan_match_count(src.as_str(), b"\x7FELFaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_10_matches_with_pdf_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:10:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint32(0) == 0x46445025"));
    assert_eq!(scan_match_count(src.as_str(), b"%PDFaaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_11_matches_with_swf_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:11:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint8(0) == 0x46 or uint8(0) == 0x43 or uint8(0) == 0x5A"));
    assert!(src.contains("uint8(1) == 0x57 and uint8(2) == 0x53"));
    assert_eq!(scan_match_count(src.as_str(), b"FWSaaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_target_type_12_matches_with_java_class_guard() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:12:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("uint32(0) == 0xBEBAFECA"));
    assert_eq!(
        scan_match_count(src.as_str(), b"\xCA\xFE\xBA\xBEaaaxxxbbb"),
        1
    );
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_invalid_target_strict_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:8:$12:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("target_type=8 (expected 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, or 12)"));
    assert_eq!(scan_match_count(src.as_str(), b"MZaaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_group_out_of_range_strict_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:0:$32:626262").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("offset group $32 outside 0..31"));
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_non_representable_body_strict_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![NdbSignature::parse("D1:0:$12:AA{-15}BB").unwrap().to_ir()];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains(
        "ndb macro link 'D1' for group $12 is not representable in strict YARA lowering"
    ));
    assert!(src.contains("ndb signed jump"));
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_mixed_members_ignores_bad_and_matches_good() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:0:$12:AA{-15}BB").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:626262").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains(
        "ndb macro link 'D1' for group $12 is not representable in strict YARA lowering"
    ));
    assert!(src.contains("macro-group `$12$` resolved via linked ndb members [D2]"));
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxxbbb"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxbbb"), 0);
}

#[test]
fn yara_rule_with_macro_group_linked_ndb_all_ignored_members_strict_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;616161;${6-7}12$").unwrap();
    let ndb_links = vec![
        NdbSignature::parse("D1:8:$12:626262").unwrap().to_ir(),
        NdbSignature::parse("D2:0:$12:AA{-15}BB").unwrap().to_ir(),
    ];

    let rule = yara::lower_logical_signature_with_ndb_context(&sig.to_ir(), &ndb_links).unwrap();
    let src = rule.to_string();

    assert!(src.contains("target_type=8 (expected 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, or 12)"));
    assert!(src.contains(
        "ndb macro link 'D2' for group $12 is not representable in strict YARA lowering"
    ));
    assert!(src.contains("ndb signed jump"));
    assert!(src.contains("macro-group `$12$` semantics depend on CLI_OFF_MACRO"));
    assert_eq!(scan_match_count(src.as_str(), b"aaaxxxbbb"), 0);
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
fn yara_rule_with_malformed_fuzzy_img_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#zzzzzzzzzzzzzzzz#0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("fuzzy_img format unsupported/invalid"));
    assert_eq!(
        scan_match_count(src.as_str(), b"xxfuzzy_img#zzzzzzzzzzzzzzzz#0yy"),
        0
    );
}

#[test]
fn yara_rule_with_fuzzy_img_short_hash_false_rejects_scan() {
    // ClamAV reference: unit_tests/clamscan/fuzzy_img_hash_test.py:92-105
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#abcdef#0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("fuzzy_img format unsupported/invalid"));
    assert!(src.contains("hash must be exactly 16 hex chars"));
    assert_eq!(scan_match_count(src.as_str(), b"xxfuzzy_img#abcdef#0yy"), 0);
}

#[test]
fn yara_rule_with_fuzzy_img_invalid_distance_token_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#x").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("fuzzy_img format unsupported/invalid"));
    assert!(src.contains("distance 'x' is not a valid unsigned integer"));
    assert_eq!(
        scan_match_count(src.as_str(), b"xxfuzzy_img#af2ad01ed42993c7#xyy"),
        0
    );
}

#[test]
fn yara_rule_with_fuzzy_img_too_many_separators_false_rejects_scan() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img#af2ad01ed42993c7#0#1").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("fuzzy_img format unsupported/invalid"));
    assert!(src.contains("too many '#' separators"));
    assert_eq!(
        scan_match_count(src.as_str(), b"xxfuzzy_img#af2ad01ed42993c7#0#1yy"),
        0
    );
}

#[test]
fn yara_rule_with_fuzzy_img_missing_hash_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0;fuzzy_img##0").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("fuzzy_img format unsupported/invalid"));
    assert!(src.contains("hash must be exactly 16 hex chars"));
    assert_eq!(scan_match_count(src.as_str(), b"xxfuzzy_img##0yy"), 0);
}

#[test]
fn yara_rule_with_byte_comparison_offset_0x_prefix_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0xA#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzA"), 1);
}

#[test]
fn yara_rule_with_byte_comparison_offset_plus_0x_prefix_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>+0xA#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzA"), 1);
}

#[test]
fn yara_rule_with_byte_comparison_offset_plus_octal_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>+010#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzA"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzA"), 0);
}

#[test]
fn yara_rule_with_byte_comparison_offset_plus_invalid_octal_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>+08#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("byte_comparison format unsupported/invalid"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzA"), 0);
}

#[test]
fn yara_rule_with_byte_comparison_offset_bare_hex_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0A#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("byte_comparison format unsupported/invalid"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzA"), 0);
}

#[test]
fn yara_rule_with_byte_comparison_offset_octal_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>010#ib1#=65)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    // `010` is octal (=8), so this fixture should match at offset 8 from $s0 start.
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzA"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"AAAAzzzzzzA"), 0);
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
fn yara_rule_with_non_raw_decimal_0x_prefixed_threshold_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3130;0(>>0#de2#=0xA)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"10"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"11"), 0);
}

#[test]
fn yara_rule_with_non_raw_decimal_plus_0x_prefixed_threshold_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3130;0(>>0#de2#=+0xA)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"10"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"11"), 0);
}

#[test]
fn yara_rule_with_non_raw_decimal_plus_octal_threshold_matches_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=+010)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"08"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"10"), 0);
}

#[test]
fn yara_rule_with_non_raw_decimal_leading_zero_threshold_matches_octal_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=010)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert_eq!(scan_match_count(src.as_str(), b"08"), 1);
    assert_eq!(scan_match_count(src.as_str(), b"10"), 0);
}

#[test]
fn yara_rule_with_non_raw_decimal_invalid_octal_threshold_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=08)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("byte_comparison format unsupported/invalid"));
    assert_eq!(scan_match_count(src.as_str(), b"08"), 0);
}

#[test]
fn yara_rule_with_non_raw_decimal_plus_invalid_octal_threshold_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3038;0(>>0#de2#=+08)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("byte_comparison format unsupported/invalid"));
    assert_eq!(scan_match_count(src.as_str(), b"08"), 0);
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
fn yara_rule_with_non_raw_auto_base_false_rejects_scan_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;3130;0(>>0#ae2#=10)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    let data = b"xx10yy";
    assert_eq!(scan_match_count(src.as_str(), data), 0);
}

#[test]
fn yara_rule_with_non_raw_hex_width_over_clamav_limit_false_rejects_scan_fixture() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>0#he19#=1)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("non-raw hex width 19 exceeds ClamAV limit 18"));
    assert_eq!(
        scan_match_count(src.as_str(), b"AAAA0000000000000000001"),
        0
    );
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
fn yara_rule_with_raw_byte_comparison_size3_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>4#ib3#=12)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("raw size 3 unsupported"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAA012"), 0);
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
fn yara_rule_with_byte_comparison_three_clauses_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>3#de3#>100,<900,=123)")
        .unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("byte_comparison with 3 clauses unsupported"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAA123"), 0);
}

#[test]
fn yara_rule_with_byte_comparison_negative_threshold_false_rejects_scan() {
    let sig = LogicalSignature::parse("Foo.Bar-1;Target:1;0&1;41414141;0(>>3#ib2#>-1)").unwrap();
    let rule = YaraRule::try_from(&sig).unwrap();
    let src = rule.to_string();

    assert!(src.contains("negative comparison value unsupported for strict lowering"));
    assert_eq!(scan_match_count(src.as_str(), b"AAAA\x00\x10"), 0);
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

#[test]
fn idb_rule_strict_false_compiles_and_rejects_scan() {
    let icon_hash = format!("10{}", "0".repeat(122));
    let raw = format!("Icon.Sample-1:IEXPLORE:GENERIC:{icon_hash}");
    let sig = IdbSignature::parse(raw.as_str()).unwrap();
    let src = yara::render_idb_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile idb strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"MZ"), 0);
}

#[test]
fn cbc_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "VIRUSNAME Bytecode.Sample\nFUNCTIONALITY_LEVEL_MIN 51";
    let sig = CbcSignature::parse(raw).unwrap();
    let src = yara::render_cbc_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile cbc strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"MZ"), 0);
}

#[test]
fn cdb_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "Container.Sample-1:CL_TYPE_ZIP:*:.*\\.exe:10-20:20-40:0:1:*:*:120:255";
    let sig = CdbSignature::parse(raw).unwrap();
    let src = yara::render_cdb_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile cdb strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"PK\x03\x04"), 0);
}

#[test]
fn cfg_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "DOCUMENT:0x5:11:13";
    let sig = CfgSignature::parse(raw).unwrap();
    let src = yara::render_cfg_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile cfg strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"DOCUMENT:0x5:11:13"), 0);
}

#[test]
fn crb_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "Trusted.Cert-1;1;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;A1B2C3D4;010001;1;0;1;0;baseline-comment;120;255";
    let sig = CrbSignature::parse(raw).unwrap();
    let src = yara::render_crb_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile crb strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"MZ"), 0);
}

#[test]
fn pdb_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "R:.+\\.amazon\\.com([/?].*)?:20-";
    let sig = PdbSignature::parse(raw).unwrap();
    let src = yara::render_pdb_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile pdb strict-false rule");
    assert_eq!(
        scan_match_count(src.as_str(), b"https://www.amazon.com/"),
        0
    );
}

#[test]
fn wdb_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "Y:https?://safe\\.example\\.com([/?].*)?:17-";
    let sig = WdbSignature::parse(raw).unwrap();
    let src = yara::render_wdb_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile wdb strict-false rule");
    assert_eq!(
        scan_match_count(src.as_str(), b"https://safe.example.com/"),
        0
    );
}

#[test]
fn ftm_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "1:*:25504446:PDF-body:CL_TYPE_ANY:CL_TYPE_PDF:120:255";
    let sig = FtmSignature::parse(raw).unwrap();
    let src = yara::render_ftm_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ftm strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"%PDF-1.7"), 0);
}

#[test]
fn fp_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
    let sig = FpSignature::parse(raw).unwrap();
    let src = yara::render_fp_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile fp strict-false rule");
    assert_eq!(
        scan_match_count(src.as_str(), b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"),
        0
    );
}

#[test]
fn sfp_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature:73";
    let sig = SfpSignature::parse(raw).unwrap();
    let src = yara::render_sfp_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile sfp strict-false rule");
    assert_eq!(
        scan_match_count(src.as_str(), b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"),
        0
    );
}

#[test]
fn ign_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "legacy-repo:legacy-id:Eicar-Test-Signature";
    let sig = IgnSignature::parse(raw).unwrap();
    let src = yara::render_ign_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ign strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"Eicar-Test-Signature"), 0);
}

#[test]
fn ign2_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "Eicar-Test-Signature:bc356bae4c42f19a3de16e333ba3569c";
    let sig = Ign2Signature::parse(raw).unwrap();
    let src = yara::render_ign2_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ign2 strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"Eicar-Test-Signature"), 0);
}

#[test]
fn hdu_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
    let sig = HduSignature::parse(raw).unwrap();
    let src = yara::render_hdu_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile hdu strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"Eicar-Test-Signature"), 0);
}

#[test]
fn hsu_rule_strict_false_compiles_and_rejects_scan() {
    let raw =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature:73";
    let sig = HsuSignature::parse(raw).unwrap();
    let src = yara::render_hsu_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile hsu strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"Eicar-Test-Signature"), 0);
}

#[test]
fn mdu_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature:73";
    let sig = MduSignature::parse(raw).unwrap();
    let src = yara::render_mdu_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile mdu strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"Eicar-Test-Signature"), 0);
}

#[test]
fn msu_rule_strict_false_compiles_and_rejects_scan() {
    let raw =
        "45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Eicar-Test-Signature:73";
    let sig = MsuSignature::parse(raw).unwrap();
    let src = yara::render_msu_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile msu strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"Eicar-Test-Signature"), 0);
}

#[test]
fn ndu_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "PUA.Win.Packer.YodaProt-1:1:EP+0:e803000000eb01??bb55000000e803000000eb01??e88e000000e803000000eb01??e881000000e803000000eb01??e8b7000000e803000000eb01??e8aa000000e803000000eb01??83fb55e803000000eb01??752d:18";
    let sig = NduSignature::parse(raw).unwrap();
    let src = yara::render_ndu_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ndu strict-false rule");
    assert_eq!(
        scan_match_count(src.as_str(), b"PUA.Win.Packer.YodaProt-1"),
        0
    );
}

#[test]
fn info_rule_strict_false_compiles_and_rejects_scan() {
    let raw =
        "ClamAV-VDB:14 Feb 2026 07-25 +0000:27912:355104:90:X:X:svc.clamav-publisher:1771053920";
    let sig = InfoSignature::parse(raw).unwrap();
    let src = yara::render_info_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile info strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"ClamAV-VDB"), 0);
}

#[test]
fn ldu_rule_strict_false_compiles_and_rejects_scan() {
    let raw = "PUA.CVE_2012_0198;Engine:51-255,Target:3;0&1;636C6173;72756E";
    let sig = LduSignature::parse(raw).unwrap();
    let src = yara::render_ldu_signature(&sig.to_ir());

    yara_x::compile(src.as_str()).expect("yara-x failed to compile ldu strict-false rule");
    assert_eq!(scan_match_count(src.as_str(), b"PUA.CVE_2012_0198"), 0);
}
