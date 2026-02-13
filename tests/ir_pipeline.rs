use sig2yar::{
    parser::{
        cbc::CbcSignature, cdb::CdbSignature, crb::CrbSignature, fp::FpSignature,
        ftm::FtmSignature, hash::HashSignature, idb::IdbSignature, ign::IgnSignature,
        ign2::Ign2Signature, ldu::LduSignature, logical::LogicalSignature, pdb::PdbSignature,
        sfp::SfpSignature, wdb::WdbSignature,
    },
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
fn ldu_ir_render_matches_display() {
    let raw = "PUA.CVE_2012_0198;Engine:51-255,Target:3;0&1;636C6173;72756E";
    let sig = LduSignature::parse(raw).expect("ldu parse failed");

    let rendered = yara::render_ldu_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn idb_ir_render_matches_display() {
    let icon_hash = format!("10{}", "0".repeat(122));
    let raw = format!("Icon.Test:GROUP_A:GROUP_B:{icon_hash}");
    let sig = IdbSignature::parse(raw.as_str()).expect("idb parse failed");

    let rendered = yara::render_idb_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn cbc_ir_render_matches_display() {
    let raw = "VIRUSNAME Bytecode.Sample\nFUNCTIONALITY_LEVEL_MIN 51";
    let sig = CbcSignature::parse(raw).expect("cbc parse failed");

    let rendered = yara::render_cbc_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn cdb_ir_render_matches_display() {
    let raw = "Container.Test-1:CL_TYPE_ZIP:*:.*\\.exe:10-20:20-40:0:1:*:*:120:255";
    let sig = CdbSignature::parse(raw).expect("cdb parse failed");

    let rendered = yara::render_cdb_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn crb_ir_render_matches_display() {
    let raw = "Trusted.Cert-1;1;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;A1B2C3D4;010001;1;0;1;0;baseline-comment;120;255";
    let sig = CrbSignature::parse(raw).expect("crb parse failed");

    let rendered = yara::render_crb_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn pdb_ir_render_matches_display() {
    let raw = "H:amazon.com:20-30";
    let sig = PdbSignature::parse(raw).expect("pdb parse failed");

    let rendered = yara::render_pdb_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn wdb_ir_render_matches_display() {
    let raw = "M:www\\.google\\.ro:www\\.google\\.com:20-30";
    let sig = WdbSignature::parse(raw).expect("wdb parse failed");

    let rendered = yara::render_wdb_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn ftm_ir_render_matches_display() {
    let raw = "1:*:25504446:PDF-body:CL_TYPE_ANY:CL_TYPE_PDF:120:255";
    let sig = FtmSignature::parse(raw).expect("ftm parse failed");

    let rendered = yara::render_ftm_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn fp_ir_render_matches_display() {
    let raw = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
    let sig = FpSignature::parse(raw).expect("fp parse failed");

    let rendered = yara::render_fp_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn sfp_ir_render_matches_display() {
    let raw =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature";
    let sig = SfpSignature::parse(raw).expect("sfp parse failed");

    let rendered = yara::render_sfp_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn ign_ir_render_matches_display() {
    let raw = "Eicar-Test-Signature:bc356bae4c42f19a3de16e333ba3569c";
    let sig = IgnSignature::parse(raw).expect("ign parse failed");

    let rendered = yara::render_ign_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}

#[test]
fn ign2_ir_render_matches_display() {
    let raw = "legacy-repo:legacy-id:Eicar-Test-Signature";
    let sig = Ign2Signature::parse(raw).expect("ign2 parse failed");

    let rendered = yara::render_ign2_signature(&sig.to_ir());
    assert_eq!(rendered, sig.to_string());
}
