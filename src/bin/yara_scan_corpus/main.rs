use anyhow::{Context, Result};
use clap::Parser;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "yara-scan-corpus")]
#[command(
    about = "Scan a file corpus with YARA rules and emit <relative_path>\\t<rule_identifier> hits"
)]
struct Args {
    /// Path to the YARA rules file.
    #[arg(long)]
    rules: PathBuf,

    /// Directory containing files to scan (recursive).
    #[arg(long)]
    corpus: PathBuf,

    /// Output TSV file path.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.rules.is_file() {
        anyhow::bail!("rules file not found: {}", args.rules.display());
    }
    if !args.corpus.is_dir() {
        anyhow::bail!("corpus directory not found: {}", args.corpus.display());
    }

    let source = fs::read_to_string(&args.rules)
        .with_context(|| format!("failed to read rules file: {}", args.rules.display()))?;
    let rules = yara_x::compile(source.as_str())
        .with_context(|| format!("failed to compile YARA rules from {}", args.rules.display()))?;

    if let Some(parent) = args.out.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output dir: {}", parent.display()))?;
    }

    let file = File::create(&args.out)
        .with_context(|| format!("failed to create output file: {}", args.out.display()))?;
    let mut writer = BufWriter::new(file);

    let files = collect_files_recursive(&args.corpus)?;

    for path in files {
        let data = fs::read(&path)
            .with_context(|| format!("failed to read corpus file: {}", path.display()))?;
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner
            .scan(data.as_slice())
            .with_context(|| format!("failed to scan file: {}", path.display()))?;

        let rel = path.strip_prefix(&args.corpus).unwrap_or(path.as_path());
        let rel = rel.to_string_lossy().replace('\\', "/");

        for matched in results.matching_rules() {
            writeln!(writer, "{rel}\t{}", matched.identifier())
                .with_context(|| format!("failed to write result row for {}", path.display()))?;
        }
    }

    writer.flush().context("failed to flush output")?;
    Ok(())
}

fn collect_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .with_context(|| format!("failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}
