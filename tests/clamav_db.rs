use sig2yar::parser::{
    cdb::CdbSignature, hash::HashSignature, idb::IdbSignature, logical::LogicalSignature,
    ndb::NdbSignature,
};
use sig2yar::yara::{self, YaraRule};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const MAX_ERROR_SAMPLES: usize = 20;
const DEFAULT_SAMPLE_SIZE: usize = 50;
const DEFAULT_SEED: u64 = 0x73696732796172;

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 { DEFAULT_SEED } else { seed };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn gen_range(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next_u64() % upper as u64) as usize
    }
}

#[derive(Clone)]
struct Sample {
    line: String,
    origin: String,
}

fn clamav_db_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("CLAMAV_DB_DIR") {
        let path = PathBuf::from(dir);
        return path.exists().then_some(path);
    }

    let default = PathBuf::from("clamav-db/unpacked");
    default.exists().then_some(default)
}

fn clamav_db_required() -> bool {
    matches!(
        std::env::var("CLAMAV_DB_REQUIRED").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn collect_files(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }

            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if exts.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                files.push(path);
            }
        }
    }

    files
}

fn parse_seed() -> u64 {
    std::env::var("CLAMAV_SAMPLE_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEED)
}

fn parse_sample_size() -> usize {
    std::env::var("CLAMAV_SAMPLE_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_SAMPLE_SIZE)
}

fn sample_logical_signatures(db_dir: &Path, sample_size: usize, seed: u64) -> Vec<Sample> {
    let files = collect_files(db_dir, &["ldb"]);
    let mut rng = XorShift64::new(seed);
    let mut samples: Vec<Sample> = Vec::new();
    let mut seen = 0usize;

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            seen += 1;
            let sample = Sample {
                line: line.to_string(),
                origin: format!("{}:{}", path.display(), line_no + 1),
            };

            if samples.len() < sample_size {
                samples.push(sample);
                continue;
            }

            let idx = rng.gen_range(seen);
            if idx < sample_size {
                samples[idx] = sample;
            }
        }
    }

    samples
}

fn sample_ndb_signatures(db_dir: &Path, sample_size: usize, seed: u64) -> Vec<Sample> {
    let files = collect_files(db_dir, &["ndb"]);
    let mut rng = XorShift64::new(seed);
    let mut samples: Vec<Sample> = Vec::new();
    let mut seen = 0usize;

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            seen += 1;
            let sample = Sample {
                line: line.to_string(),
                origin: format!("{}:{}", path.display(), line_no + 1),
            };

            if samples.len() < sample_size {
                samples.push(sample);
                continue;
            }

            let idx = rng.gen_range(seen);
            if idx < sample_size {
                samples[idx] = sample;
            }
        }
    }

    samples
}

fn sample_idb_signatures(db_dir: &Path, sample_size: usize, seed: u64) -> Vec<Sample> {
    let files = collect_files(db_dir, &["idb"]);
    let mut rng = XorShift64::new(seed);
    let mut samples: Vec<Sample> = Vec::new();
    let mut seen = 0usize;

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            seen += 1;
            let sample = Sample {
                line: line.to_string(),
                origin: format!("{}:{}", path.display(), line_no + 1),
            };

            if samples.len() < sample_size {
                samples.push(sample);
                continue;
            }

            let idx = rng.gen_range(seen);
            if idx < sample_size {
                samples[idx] = sample;
            }
        }
    }

    samples
}

fn sample_cdb_signatures(db_dir: &Path, sample_size: usize, seed: u64) -> Vec<Sample> {
    let files = collect_files(db_dir, &["cdb"]);
    let mut rng = XorShift64::new(seed);
    let mut samples: Vec<Sample> = Vec::new();
    let mut seen = 0usize;

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            seen += 1;
            let sample = Sample {
                line: line.to_string(),
                origin: format!("{}:{}", path.display(), line_no + 1),
            };

            if samples.len() < sample_size {
                samples.push(sample);
                continue;
            }

            let idx = rng.gen_range(seen);
            if idx < sample_size {
                samples[idx] = sample;
            }
        }
    }

    samples
}

type NdbPredicate = fn(&NdbSignature<'_>) -> bool;

struct NdbFeatureSpec {
    name: &'static str,
    predicate: NdbPredicate,
}

fn ndb_feature_specs() -> Vec<NdbFeatureSpec> {
    vec![
        NdbFeatureSpec {
            name: "target_type_0",
            predicate: |s| s.target_type == "0",
        },
        NdbFeatureSpec {
            name: "target_type_1",
            predicate: |s| s.target_type == "1",
        },
        NdbFeatureSpec {
            name: "target_type_2",
            predicate: |s| s.target_type == "2",
        },
        NdbFeatureSpec {
            name: "target_type_3",
            predicate: |s| s.target_type == "3",
        },
        NdbFeatureSpec {
            name: "target_type_4",
            predicate: |s| s.target_type == "4",
        },
        NdbFeatureSpec {
            name: "target_type_5",
            predicate: |s| s.target_type == "5",
        },
        NdbFeatureSpec {
            name: "target_type_6",
            predicate: |s| s.target_type == "6",
        },
        NdbFeatureSpec {
            name: "target_type_7",
            predicate: |s| s.target_type == "7",
        },
        NdbFeatureSpec {
            name: "target_type_9",
            predicate: |s| s.target_type == "9",
        },
        NdbFeatureSpec {
            name: "target_type_10",
            predicate: |s| s.target_type == "10",
        },
        NdbFeatureSpec {
            name: "target_type_11",
            predicate: |s| s.target_type == "11",
        },
        NdbFeatureSpec {
            name: "target_type_12",
            predicate: |s| s.target_type == "12",
        },
        NdbFeatureSpec {
            name: "offset_any",
            predicate: |s| s.offset == "*",
        },
        NdbFeatureSpec {
            name: "offset_abs",
            predicate: |s| is_ascii_digits(s.offset),
        },
        NdbFeatureSpec {
            name: "offset_abs_range",
            predicate: |s| is_ascii_digit_range(s.offset),
        },
        NdbFeatureSpec {
            name: "offset_ep",
            predicate: |s| s.offset.starts_with("EP"),
        },
        NdbFeatureSpec {
            name: "offset_section",
            predicate: |s| is_section_offset(s.offset),
        },
        NdbFeatureSpec {
            name: "offset_sl",
            predicate: |s| s.offset.starts_with("SL+"),
        },
        NdbFeatureSpec {
            name: "offset_se",
            predicate: |s| s.offset.starts_with("SE"),
        },
        NdbFeatureSpec {
            name: "offset_eof",
            predicate: |s| s.offset.starts_with("EOF"),
        },
        NdbFeatureSpec {
            name: "body_star",
            predicate: |s| s.body.contains('*'),
        },
        NdbFeatureSpec {
            name: "body_fixed_jump",
            predicate: |s| has_curly_token(s.body, |tok| is_ascii_digits(tok)),
        },
        NdbFeatureSpec {
            name: "body_negative_jump",
            predicate: |s| has_curly_token(s.body, is_negative_jump_token),
        },
        NdbFeatureSpec {
            name: "body_open_jump",
            predicate: |s| has_curly_token(s.body, is_open_ended_jump_token),
        },
        NdbFeatureSpec {
            name: "body_range_jump",
            predicate: |s| has_curly_token(s.body, is_positive_range_jump_token),
        },
        NdbFeatureSpec {
            name: "body_alt",
            predicate: |s| s.body.contains('(') && s.body.contains('|') && s.body.contains(')'),
        },
        NdbFeatureSpec {
            name: "body_square",
            predicate: |s| s.body.contains('[') && s.body.contains(']'),
        },
        NdbFeatureSpec {
            name: "body_nibble_wildcard",
            predicate: |s| s.body.contains('?'),
        },
    ]
}

fn collect_ndb_feature_samples(db_dir: &Path) -> (Vec<(String, Sample)>, Vec<String>) {
    let specs = ndb_feature_specs();
    let mut found: Vec<Option<Sample>> = (0..specs.len()).map(|_| None).collect();
    let mut remaining: HashSet<usize> = (0..specs.len()).collect();

    for path in collect_files(db_dir, &["ndb"]) {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);

        for (line_no, line) in reader.lines().flatten().enumerate() {
            if remaining.is_empty() {
                break;
            }

            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parsed = match NdbSignature::parse(line) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };

            let sample = Sample {
                line: line.to_string(),
                origin: format!("{}:{}", path.display(), line_no + 1),
            };

            let matches: Vec<usize> = remaining
                .iter()
                .copied()
                .filter(|idx| (specs[*idx].predicate)(&parsed))
                .collect();

            for idx in matches {
                found[idx] = Some(sample.clone());
                remaining.remove(&idx);
            }
        }

        if remaining.is_empty() {
            break;
        }
    }

    let mut covered = Vec::new();
    let mut missing = Vec::new();

    for (idx, spec) in specs.iter().enumerate() {
        match &found[idx] {
            Some(sample) => covered.push((spec.name.to_string(), sample.clone())),
            None => missing.push(spec.name.to_string()),
        }
    }

    (covered, missing)
}

fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

fn is_ascii_digit_range(value: &str) -> bool {
    let Some((lhs, rhs)) = value.split_once(',') else {
        return false;
    };
    is_ascii_digits(lhs) && is_ascii_digits(rhs)
}

fn is_section_offset(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('S') else {
        return false;
    };
    !rest.starts_with('L') && !rest.starts_with('E') && rest.contains('+')
}

fn has_curly_token(body: &str, predicate: fn(&str) -> bool) -> bool {
    let mut pos = 0usize;
    while let Some(open_rel) = body[pos..].find('{') {
        let open = pos + open_rel;
        let Some(close_rel) = body[open + 1..].find('}') else {
            break;
        };
        let close = open + 1 + close_rel;
        let token = body[open + 1..close].trim();
        if predicate(token) {
            return true;
        }
        pos = close + 1;
    }
    false
}

fn is_negative_jump_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('-') else {
        return false;
    };
    is_ascii_digits(rest)
}

fn is_open_ended_jump_token(token: &str) -> bool {
    let Some(rest) = token.strip_suffix('-') else {
        return false;
    };
    is_ascii_digits(rest)
}

fn is_positive_range_jump_token(token: &str) -> bool {
    let Some((lhs, rhs)) = token.split_once('-') else {
        return false;
    };
    is_ascii_digits(lhs) && is_ascii_digits(rhs)
}

#[test]
fn parse_hash_signatures_from_clamav_db() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let files = collect_files(&db_dir, &["hdb", "hsb", "mdb", "msb", "imp"]);
    if files.is_empty() {
        if clamav_db_required() {
            panic!("No hash signature files found under {:?}", db_dir);
        }
        return;
    }

    let mut total = 0usize;
    let mut failures = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            total += 1;
            match HashSignature::parse(line) {
                Ok(sig) => {
                    let _ = sig.to_string();
                }
                Err(err) => {
                    failures += 1;
                    if samples.len() < MAX_ERROR_SAMPLES {
                        samples.push(format!("{}:{}: {}", path.display(), line_no + 1, err));
                    }
                }
            }
        }
    }

    if total == 0 {
        panic!("No hash signatures found under {:?}", db_dir);
    }
    if failures > 0 {
        panic!(
            "Failed to parse {failures} of {total} hash signatures. Samples:\n{}",
            samples.join("\n")
        );
    }
}

#[test]
fn parse_logical_signatures_from_clamav_db() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let files = collect_files(&db_dir, &["ldb"]);
    if files.is_empty() {
        if clamav_db_required() {
            panic!("No .ldb files found under {:?}", db_dir);
        }
        return;
    }

    let mut total = 0usize;
    let mut failures = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            total += 1;
            match LogicalSignature::parse(line) {
                Ok(sig) => {
                    let _ = sig.to_string();
                }
                Err(err) => {
                    failures += 1;
                    if samples.len() < MAX_ERROR_SAMPLES {
                        samples.push(format!("{}:{}: {}", path.display(), line_no + 1, err));
                    }
                }
            }
        }
    }

    if total == 0 {
        panic!("No logical signatures found under {:?}", db_dir);
    }
    if failures > 0 {
        panic!(
            "Failed to parse {failures} of {total} logical signatures. Samples:\n{}",
            samples.join("\n")
        );
    }
}

#[test]
fn parse_ndb_signatures_from_clamav_db() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let files = collect_files(&db_dir, &["ndb"]);
    if files.is_empty() {
        if clamav_db_required() {
            panic!("No .ndb files found under {:?}", db_dir);
        }
        return;
    }

    let mut total = 0usize;
    let mut failures = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            total += 1;
            if let Err(err) = NdbSignature::parse(line) {
                failures += 1;
                if samples.len() < MAX_ERROR_SAMPLES {
                    samples.push(format!("{}:{}: {}", path.display(), line_no + 1, err));
                }
            }
        }
    }

    if total == 0 {
        panic!("No ndb signatures found under {:?}", db_dir);
    }
    if failures > 0 {
        panic!(
            "Failed to parse {failures} of {total} ndb signatures. Samples:\n{}",
            samples.join("\n")
        );
    }
}

#[test]
fn parse_idb_signatures_from_clamav_db() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let files = collect_files(&db_dir, &["idb"]);
    if files.is_empty() {
        if clamav_db_required() {
            panic!("No .idb files found under {:?}", db_dir);
        }
        return;
    }

    let mut total = 0usize;
    let mut failures = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            total += 1;
            if let Err(err) = IdbSignature::parse(line) {
                failures += 1;
                if samples.len() < MAX_ERROR_SAMPLES {
                    samples.push(format!("{}:{}: {}", path.display(), line_no + 1, err));
                }
            }
        }
    }

    if total == 0 {
        panic!("No idb signatures found under {:?}", db_dir);
    }
    if failures > 0 {
        panic!(
            "Failed to parse {failures} of {total} idb signatures. Samples:\n{}",
            samples.join("\n")
        );
    }
}

#[test]
fn parse_cdb_signatures_from_clamav_db() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let files = collect_files(&db_dir, &["cdb"]);
    if files.is_empty() {
        if clamav_db_required() {
            panic!("No .cdb files found under {:?}", db_dir);
        }
        return;
    }

    let mut total = 0usize;
    let mut failures = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (line_no, line) in reader.lines().flatten().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            total += 1;
            if let Err(err) = CdbSignature::parse(line) {
                failures += 1;
                if samples.len() < MAX_ERROR_SAMPLES {
                    samples.push(format!("{}:{}: {}", path.display(), line_no + 1, err));
                }
            }
        }
    }

    if total == 0 {
        panic!("No cdb signatures found under {:?}", db_dir);
    }
    if failures > 0 {
        panic!(
            "Failed to parse {failures} of {total} cdb signatures. Samples:\n{}",
            samples.join("\n")
        );
    }
}

#[test]
fn yara_rules_from_db_samples_compile() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let sample_size = parse_sample_size();
    let seed = parse_seed();
    let samples = sample_logical_signatures(&db_dir, sample_size, seed);

    if samples.is_empty() {
        if clamav_db_required() {
            panic!("No logical signatures found under {:?}", db_dir);
        }
        return;
    }

    for sample in samples {
        let sig = LogicalSignature::parse(&sample.line)
            .unwrap_or_else(|e| panic!("{}: parse failed: {}", sample.origin, e));
        let rule = YaraRule::try_from(&sig)
            .unwrap_or_else(|e| panic!("{}: convert failed: {}", sample.origin, e));
        let src = rule.to_string();

        yara_x::compile(src.as_str())
            .unwrap_or_else(|e| panic!("{}: compile failed: {}", sample.origin, e));
    }
}

#[test]
fn yara_ndb_rules_from_db_samples_compile() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let sample_size = parse_sample_size();
    let seed = parse_seed();
    let samples = sample_ndb_signatures(&db_dir, sample_size, seed);

    if samples.is_empty() {
        if clamav_db_required() {
            panic!("No ndb signatures found under {:?}", db_dir);
        }
        return;
    }

    for sample in samples {
        let sig = NdbSignature::parse(&sample.line)
            .unwrap_or_else(|e| panic!("{}: parse failed: {}", sample.origin, e));
        let ir = sig.to_ir();
        let src = yara::render_ndb_signature(&ir);

        yara_x::compile(src.as_str())
            .unwrap_or_else(|e| panic!("{}: compile failed: {}", sample.origin, e));
    }
}

#[test]
fn yara_idb_rules_from_db_samples_compile() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let sample_size = parse_sample_size();
    let seed = parse_seed();
    let samples = sample_idb_signatures(&db_dir, sample_size, seed);

    if samples.is_empty() {
        if clamav_db_required() {
            panic!("No idb signatures found under {:?}", db_dir);
        }
        return;
    }

    for sample in samples {
        let sig = IdbSignature::parse(&sample.line)
            .unwrap_or_else(|e| panic!("{}: parse failed: {}", sample.origin, e));
        let ir = sig.to_ir();
        let src = yara::render_idb_signature(&ir);

        yara_x::compile(src.as_str())
            .unwrap_or_else(|e| panic!("{}: compile failed: {}", sample.origin, e));
    }
}

#[test]
fn yara_cdb_rules_from_db_samples_compile() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let sample_size = parse_sample_size();
    let seed = parse_seed();
    let samples = sample_cdb_signatures(&db_dir, sample_size, seed);

    if samples.is_empty() {
        if clamav_db_required() {
            panic!("No cdb signatures found under {:?}", db_dir);
        }
        return;
    }

    for sample in samples {
        let sig = CdbSignature::parse(&sample.line)
            .unwrap_or_else(|e| panic!("{}: parse failed: {}", sample.origin, e));
        let ir = sig.to_ir();
        let src = yara::render_cdb_signature(&ir);

        yara_x::compile(src.as_str())
            .unwrap_or_else(|e| panic!("{}: compile failed: {}", sample.origin, e));
    }
}

#[test]
fn yara_ndb_feature_coverage_samples_compile() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let (samples, missing) = collect_ndb_feature_samples(&db_dir);

    if samples.is_empty() {
        if clamav_db_required() {
            panic!("No ndb signatures found under {:?}", db_dir);
        }
        return;
    }

    if !missing.is_empty() {
        panic!(
            "NDB feature coverage missing samples for: {}",
            missing.join(", ")
        );
    }

    for (feature, sample) in samples {
        let sig = NdbSignature::parse(&sample.line)
            .unwrap_or_else(|e| panic!("[{feature}] {}: parse failed: {}", sample.origin, e));
        let ir = sig.to_ir();
        let src = yara::render_ndb_signature(&ir);

        yara_x::compile(src.as_str())
            .unwrap_or_else(|e| panic!("[{feature}] {}: compile failed: {}", sample.origin, e));
    }
}
