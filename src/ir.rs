#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Hash(HashSignature),
    Logical(LogicalSignature),
    Ldu(LduSignature),
    Ndb(NdbSignature),
    Idb(IdbSignature),
    Cbc(CbcSignature),
    Cdb(CdbSignature),
    Crb(CrbSignature),
    Pdb(PdbSignature),
    Wdb(WdbSignature),
    Ftm(FtmSignature),
    Fp(FpSignature),
    Sfp(SfpSignature),
    Ign(IgnSignature),
    Ign2(Ign2Signature),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashSignature {
    pub name: String,
    pub hash: String,
    pub hash_type: HashType,
    pub source: HashSource,
    pub min_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashSource {
    File { size: Option<u64> },
    Section { size: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalSignature {
    pub name: String,
    pub target_description: TargetDescription,
    pub expression: LogicalExpression,
    pub subsignatures: Vec<Subsignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LduSignature {
    pub raw: String,
    pub signature_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdbSignature {
    pub name: String,
    pub target_type: String,
    pub offset: String,
    pub body: String,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdbSignature {
    pub name: String,
    pub group1: String,
    pub group2: String,
    pub icon_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbcSignature {
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdbSignature {
    pub name: String,
    pub container_type: String,
    pub container_size: String,
    pub filename_regexp: String,
    pub file_size_in_container: String,
    pub file_size_real: String,
    pub is_encrypted: String,
    pub file_pos: String,
    pub res1: String,
    pub res2: String,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrbSignature {
    pub name: String,
    pub trusted: String,
    pub subject: String,
    pub serial: String,
    pub pubkey: String,
    pub exponent: String,
    pub code_sign: String,
    pub time_sign: String,
    pub cert_sign: String,
    pub not_before: String,
    pub comment: String,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSignature {
    pub raw: String,
    pub record_type: String,
    pub filter_flags: Option<String>,
    pub pattern: String,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdbSignature {
    pub raw: String,
    pub record_type: String,
    pub filter_flags: Option<String>,
    pub pattern: String,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtmSignature {
    pub magic_type: u32,
    pub offset: String,
    pub magic_bytes: String,
    pub name: String,
    pub required_type: String,
    pub detected_type: String,
    pub min_flevel: Option<u32>,
    pub max_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpSignature {
    pub name: String,
    pub hash: String,
    pub hash_type: HashType,
    pub size: Option<u64>,
    pub min_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfpSignature {
    pub name: String,
    pub hash: String,
    pub hash_type: HashType,
    pub size: Option<u64>,
    pub min_flevel: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnSignature {
    pub raw: String,
    pub signature_name: String,
    pub md5: Option<String>,
    pub legacy_prefix_1: Option<String>,
    pub legacy_prefix_2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ign2Signature {
    pub raw: String,
    pub signature_name: String,
    pub md5: Option<String>,
    pub legacy_prefix_1: Option<String>,
    pub legacy_prefix_2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDescription {
    pub raw: String,
    pub target_type: Option<String>,
    pub file_size: Option<(u64, u64)>,
    pub entry_point: Option<(u64, u64)>,
    pub number_of_sections: Option<(u64, u64)>,
    pub container: Option<String>,
    pub intermediates: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalExpression {
    SubExpression(usize),
    And(Vec<LogicalExpression>),
    Or(Vec<LogicalExpression>),
    MatchCount(Box<LogicalExpression>, usize),
    MultiMatchCount(Box<LogicalExpression>, usize, usize),
    Gt(Box<LogicalExpression>, usize),
    MultiGt(Box<LogicalExpression>, usize, usize),
    Lt(Box<LogicalExpression>, usize),
    MultiLt(Box<LogicalExpression>, usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsignature {
    pub raw: String,
    pub pattern: SubsignaturePattern,
    pub modifiers: Vec<SubsignatureModifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubsignaturePattern {
    Hex(String),
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubsignatureModifier {
    CaseInsensitive,
    Wide,
    Fullword,
    Ascii,
    Unknown(char),
}
