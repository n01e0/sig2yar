use sig2yar::parser::logical::LogicalSignature;
use sig2yar::yara::YaraRule;

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
