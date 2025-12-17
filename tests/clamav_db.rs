use sig2yar::parser::{hash::HashSignature, logical::LogicalSignature};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const MAX_ERROR_SAMPLES: usize = 20;

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

#[test]
fn parse_hash_signatures_from_clamav_db() {
    let Some(db_dir) = clamav_db_dir() else {
        if clamav_db_required() {
            panic!("ClamAV DB is required but not found.");
        }
        return;
    };

    let files = collect_files(&db_dir, &["hdb"]);
    if files.is_empty() {
        if clamav_db_required() {
            panic!("No .hdb files found under {:?}", db_dir);
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
                        samples.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            line_no + 1,
                            err
                        ));
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
                        samples.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            line_no + 1,
                            err
                        ));
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
