#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Hash(HashSignature),
    Logical(LogicalSignature),
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
pub struct TargetDescription {
    pub raw: String,
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
