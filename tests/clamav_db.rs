use sig2yar::parser::{hash::HashSignature, logical::LogicalSignature, ndb::NdbSignature};
use sig2yar::yara::{self, YaraRule};
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
