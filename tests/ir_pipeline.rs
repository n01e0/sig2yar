use sig2yar::{
    parser::{hash::HashSignature, idb::IdbSignature, logical::LogicalSignature},
    yara,
};

#[test]
fn hash_ir_render_matches_display() {
    let sig = HashSignature::parse("44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature")
        .expect("hash parse failed");

    let rendered = yara::render_hash_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn logical_ir_lower_matches_display() {
    let sig =
        LogicalSignature::parse("Foo.Bar-1;Target:1;0;41414141").expect("logical parse failed");

    let rule = yara::lower_logical_signature(&sig.to_ir()).expect("lowering failed");
    assert_eq!(rule.to_string(), sig.to_string());
}

#[test]
fn idb_ir_render_matches_display() {
    let icon_hash = format!("10{}", "0".repeat(122));
    let raw = format!("Icon.Test:GROUP_A:GROUP_B:{icon_hash}");
    let sig = IdbSignature::parse(raw.as_str()).expect("idb parse failed");

    let rendered = yara::render_idb_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}
