#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DB_DIR="${CLAMAV_DB_DIR:-${ROOT_DIR}/clamav-db/unpacked}"
CORPUS_DIR="${CLAMAV_DIFF_CORPUS_DIR:-}"
SAMPLE_SIZE="${CLAMAV_DIFF_SAMPLE_SIZE:-200}"
SEED="${CLAMAV_DIFF_SEED:-7331}"
OUT_DIR="${CLAMAV_DIFF_OUT_DIR:-${ROOT_DIR}/target/validation/scan-diff}"

if [[ -z "${CORPUS_DIR}" ]]; then
  echo "CLAMAV_DIFF_CORPUS_DIR is required" >&2
  echo "example: CLAMAV_DIFF_CORPUS_DIR=${ROOT_DIR}/target/validation/corpus scripts/logical-scan-diff.sh" >&2
  exit 2
fi

if [[ ! -d "${DB_DIR}" ]]; then
  echo "ClamAV DB dir not found: ${DB_DIR}" >&2
  exit 2
fi

if [[ ! -d "${CORPUS_DIR}" ]]; then
  echo "Corpus dir not found: ${CORPUS_DIR}" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"
RUN_DIR="$(mktemp -d "${OUT_DIR}/run.XXXXXX")"

SAMPLE_LDB="${RUN_DIR}/sample.ldb"
RULES_FILE="${RUN_DIR}/sample.yar"
RULE_MAP="${RUN_DIR}/rule_map.tsv"
DUP_RULES="${RUN_DIR}/skipped_rule_id_collisions.tsv"
EFFECTIVE_NAMES="${RUN_DIR}/effective_names.txt"
YARA_HITS="${RUN_DIR}/yara_hits.tsv"
CLAMAV_OUT="${RUN_DIR}/clamscan.out"
CLAMAV_ERR="${RUN_DIR}/clamscan.err"
SUMMARY_JSON="${RUN_DIR}/summary.json"
MISMATCH_TSV="${RUN_DIR}/mismatches.tsv"
REPORT_MD="${RUN_DIR}/report.md"

python3 - "${DB_DIR}" "${SAMPLE_SIZE}" "${SEED}" "${SAMPLE_LDB}" <<'PY'
import pathlib
import random
import sys

if len(sys.argv) != 5:
    raise SystemExit("usage: <db_dir> <sample_size> <seed> <out>")

db_dir = pathlib.Path(sys.argv[1])
sample_size = max(1, int(sys.argv[2]))
seed = int(sys.argv[3])
out = pathlib.Path(sys.argv[4])

rng = random.Random(seed)
reservoir = []
seen = 0

for path in sorted(db_dir.rglob("*.ldb")):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            seen += 1
            if len(reservoir) < sample_size:
                reservoir.append(line)
            else:
                i = rng.randrange(seen)
                if i < sample_size:
                    reservoir[i] = line

out.write_text("\n".join(reservoir) + ("\n" if reservoir else ""), encoding="utf-8")
PY

if [[ ! -s "${SAMPLE_LDB}" ]]; then
  echo "No logical signatures sampled from ${DB_DIR}" >&2
  exit 1
fi

(
  cd "${ROOT_DIR}"
  cargo build --quiet --bin sig2yar --bin yara_scan_corpus
)

SIG2YAR_BIN="${ROOT_DIR}/target/debug/sig2yar"
YARA_SCAN_BIN="${ROOT_DIR}/target/debug/yara_scan_corpus"

: > "${RULES_FILE}"
: > "${RULE_MAP}"
: > "${DUP_RULES}"

declare -A seen_rule
while IFS= read -r sig; do
  [[ -z "${sig}" ]] && continue

  rule_text="$(${SIG2YAR_BIN} logical "${sig}")"
  rule_id="$(printf '%s\n' "${rule_text}" | awk '/^rule /{print $2; exit}')"
  if [[ -z "${rule_id}" ]]; then
    echo "failed to extract rule id for signature: ${sig}" >&2
    exit 1
  fi

  orig_name="${sig%%;*}"
  if [[ -n "${seen_rule[${rule_id}]+x}" ]]; then
    printf '%s\t%s\t%s\n' "${rule_id}" "${seen_rule[${rule_id}]}" "${orig_name}" >> "${DUP_RULES}"
    continue
  fi

  seen_rule["${rule_id}"]="${orig_name}"
  printf '%s\t%s\n' "${rule_id}" "${orig_name}" >> "${RULE_MAP}"
  printf '%s\n\n' "${rule_text}" >> "${RULES_FILE}"
done < "${SAMPLE_LDB}"

if [[ ! -s "${RULE_MAP}" ]]; then
  echo "No generated YARA rules after deduplication" >&2
  exit 1
fi

cut -f2 "${RULE_MAP}" | sort -u > "${EFFECTIVE_NAMES}"

"${YARA_SCAN_BIN}" --rules "${RULES_FILE}" --corpus "${CORPUS_DIR}" --out "${YARA_HITS}"

(
  cd "${ROOT_DIR}"
  set +e
  docker compose run --rm \
    -v "${CORPUS_DIR}:/scan:ro" \
    -v "${RUN_DIR}:/work" \
    --entrypoint /bin/sh \
    clamav \
    -lc 'set -e; set +e; clamscan -r --allmatch --infected --no-summary --database /var/lib/clamav/unpacked /scan > /work/clamscan.out 2> /work/clamscan.err; ec=$?; set -e; if [ "$ec" -gt 1 ]; then cat /work/clamscan.err >&2; exit "$ec"; fi; exit 0'
  ec=$?
  set -e
  if [[ "$ec" -ne 0 ]]; then
    echo "clamscan failed with exit code ${ec}" >&2
    exit "$ec"
  fi
)

python3 - "${CORPUS_DIR}" "${CLAMAV_OUT}" "${YARA_HITS}" "${RULE_MAP}" "${EFFECTIVE_NAMES}" "${RULES_FILE}" "${SUMMARY_JSON}" "${MISMATCH_TSV}" "${REPORT_MD}" <<'PY'
import collections
import json
import pathlib
import re
import sys

if len(sys.argv) != 10:
    raise SystemExit("usage: <corpus_dir> <clamscan_out> <yara_hits> <rule_map> <effective_names> <rules_file> <summary_json> <mismatch_tsv> <report_md>")

corpus_dir = pathlib.Path(sys.argv[1]).resolve()
clamscan_out = pathlib.Path(sys.argv[2])
yara_hits = pathlib.Path(sys.argv[3])
rule_map_path = pathlib.Path(sys.argv[4])
effective_names_path = pathlib.Path(sys.argv[5])
rules_file = pathlib.Path(sys.argv[6])
summary_json = pathlib.Path(sys.argv[7])
mismatch_tsv = pathlib.Path(sys.argv[8])
report_md = pathlib.Path(sys.argv[9])


def relpath(p: pathlib.Path) -> str:
    try:
        return p.resolve().relative_to(corpus_dir).as_posix()
    except Exception:
        return p.name


def unescape_yara_string(value: str) -> str:
    return value.replace(r"\\\"", '"').replace(r"\\\\", "\\")


def parse_rules_metadata(path: pathlib.Path):
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    rule_blocks = []
    current_rule_id = None
    current_lines = []

    for line in lines:
        stripped = line.strip()
        if line.startswith("rule "):
            if current_rule_id is not None:
                rule_blocks.append((current_rule_id, current_lines))
            parts = stripped.split()
            current_rule_id = parts[1] if len(parts) >= 2 else None
            current_lines = [line]
            continue

        if current_rule_id is not None:
            current_lines.append(line)

    if current_rule_id is not None:
        rule_blocks.append((current_rule_id, current_lines))

    unsupported_re = re.compile(r'^\s*clamav_unsupported\s*=\s*"((?:\\.|[^"\\])*)"\s*$')
    notes_re = re.compile(r'^\s*clamav_lowering_notes\s*=\s*"((?:\\.|[^"\\])*)"\s*$')

    info = {}
    for rid, block_lines in rule_blocks:
        unsupported_tags = []
        lowering_notes = []

        condition_expr_parts = []
        in_condition = False

        for raw in block_lines:
            if in_condition:
                stripped = raw.strip()
                if stripped == "}":
                    in_condition = False
                elif stripped:
                    condition_expr_parts.append(stripped)

            if raw.strip() == "condition:":
                in_condition = True
                continue

            m = unsupported_re.match(raw)
            if m:
                decoded = unescape_yara_string(m.group(1))
                unsupported_tags.extend(
                    t.strip() for t in decoded.split(",") if t.strip()
                )
                continue

            m = notes_re.match(raw)
            if m:
                decoded = unescape_yara_string(m.group(1))
                lowering_notes.extend(
                    t.strip() for t in decoded.split("; ") if t.strip()
                )
                continue

        condition_expr = " ".join(condition_expr_parts).strip()
        strict_false = (condition_expr == "false") or ("(false)" in condition_expr)

        info[rid] = {
            "strict_false": strict_false,
            "condition_expr": condition_expr,
            "unsupported_tags": unsupported_tags,
            "lowering_notes": lowering_notes,
        }

    return info


files = sorted([p for p in corpus_dir.rglob("*") if p.is_file()])
all_files = [relpath(p) for p in files]

rule_to_orig = {}
for raw in rule_map_path.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    rid, orig = raw.split("\t", 1)
    rule_to_orig[rid] = orig

sample_names = set(
    line.strip()
    for line in effective_names_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
)

rule_infos = parse_rules_metadata(rules_file)
name_infos = {}
for rid, orig in rule_to_orig.items():
    meta = rule_infos.get(
        rid,
        {
            "strict_false": False,
            "condition_expr": "",
            "unsupported_tags": [],
            "lowering_notes": [],
        },
    )
    name_infos[orig] = meta

clam_hits = collections.defaultdict(set)
for raw in clamscan_out.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = raw.strip()
    if not line.endswith(" FOUND"):
        continue
    if ": " not in line:
        continue
    file_part, sig_part = line.rsplit(": ", 1)
    sig_name = sig_part[:-6]  # strip " FOUND"
    if sig_name not in sample_names:
        continue

    file_path = pathlib.Path(file_part)
    if str(file_path).startswith("/scan/"):
        rel = pathlib.Path(str(file_path)[6:]).as_posix()
    elif str(file_path) == "/scan":
        rel = "."
    else:
        rel = file_path.name
    clam_hits[rel].add(sig_name)

yara_hits_map = collections.defaultdict(set)
for raw in yara_hits.read_text(encoding="utf-8", errors="ignore").splitlines():
    if not raw.strip():
        continue
    parts = raw.split("\t", 1)
    if len(parts) != 2:
        continue
    rel, rid = parts
    orig = rule_to_orig.get(rid)
    if orig is None:
        continue
    yara_hits_map[rel].add(orig)

all_keys = sorted(set(all_files) | set(clam_hits.keys()) | set(yara_hits_map.keys()))

mismatches = []
only_clamav_counter = collections.Counter()
only_yara_counter = collections.Counter()
only_clamav_strict_false_counter = collections.Counter()
only_clamav_non_strict_counter = collections.Counter()
strict_false_unsupported_counter = collections.Counter()
strict_false_notes_counter = collections.Counter()

strict_false_only_files = 0
detection_gap_files = 0
overmatch_files = 0

for rel in all_keys:
    cset = clam_hits.get(rel, set())
    yset = yara_hits_map.get(rel, set())
    only_clamav = sorted(cset - yset)
    only_yara = sorted(yset - cset)
    if not (only_clamav or only_yara):
        continue

    only_clamav_strict_false = []
    only_clamav_non_strict = []
    file_strict_false_tags = set()

    for sig_name in only_clamav:
        meta = name_infos.get(sig_name)
        if meta and meta.get("strict_false", False):
            only_clamav_strict_false.append(sig_name)
            tags = meta.get("unsupported_tags", [])
            notes = meta.get("lowering_notes", [])
            if tags:
                strict_false_unsupported_counter.update(tags)
                file_strict_false_tags.update(tags)
            else:
                strict_false_unsupported_counter.update(["<none>"])
                file_strict_false_tags.add("<none>")
            if notes:
                strict_false_notes_counter.update(notes)
        else:
            only_clamav_non_strict.append(sig_name)

    if only_clamav_non_strict:
        detection_gap_files += 1
    if only_yara:
        overmatch_files += 1
    if only_clamav_strict_false and not only_clamav_non_strict and not only_yara:
        strict_false_only_files += 1

    mismatches.append(
        {
            "file": rel,
            "only_clamav": only_clamav,
            "only_clamav_strict_false": only_clamav_strict_false,
            "only_clamav_non_strict": only_clamav_non_strict,
            "only_yara": only_yara,
            "strict_false_unsupported_tags": sorted(file_strict_false_tags),
        }
    )

    only_clamav_counter.update(only_clamav)
    only_yara_counter.update(only_yara)
    only_clamav_strict_false_counter.update(only_clamav_strict_false)
    only_clamav_non_strict_counter.update(only_clamav_non_strict)

summary = {
    "files_scanned": len(all_files),
    "sampled_rules": len(rule_to_orig),
    "clamav_hit_files": sum(1 for v in clam_hits.values() if v),
    "yara_hit_files": sum(1 for v in yara_hits_map.values() if v),
    "clamav_hit_total": sum(len(v) for v in clam_hits.values()),
    "yara_hit_total": sum(len(v) for v in yara_hits_map.values()),
    "mismatch_files": len(mismatches),
    "only_clamav_total": sum(len(item["only_clamav"]) for item in mismatches),
    "only_clamav_strict_false_total": sum(
        len(item["only_clamav_strict_false"]) for item in mismatches
    ),
    "only_clamav_non_strict_total": sum(
        len(item["only_clamav_non_strict"]) for item in mismatches
    ),
    "only_yara_total": sum(len(item["only_yara"]) for item in mismatches),
    "mismatch_category_files": {
        "strict_false_only": strict_false_only_files,
        "detection_gap": detection_gap_files,
        "overmatch": overmatch_files,
    },
    "mismatch_examples": mismatches[:20],
    "top_only_clamav": only_clamav_counter.most_common(20),
    "top_only_clamav_strict_false": only_clamav_strict_false_counter.most_common(20),
    "top_only_clamav_non_strict": only_clamav_non_strict_counter.most_common(20),
    "top_only_yara": only_yara_counter.most_common(20),
    "top_strict_false_unsupported_tags": strict_false_unsupported_counter.most_common(20),
    "top_strict_false_notes": strict_false_notes_counter.most_common(20),
}

summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

with mismatch_tsv.open("w", encoding="utf-8") as f:
    f.write(
        "file\tonly_clamav\tonly_clamav_strict_false\tonly_clamav_non_strict\tonly_yara\tstrict_false_unsupported_tags\n"
    )
    for item in mismatches:
        f.write(
            "\t".join(
                [
                    item["file"],
                    ",".join(item["only_clamav"]),
                    ",".join(item["only_clamav_strict_false"]),
                    ",".join(item["only_clamav_non_strict"]),
                    ",".join(item["only_yara"]),
                    ",".join(item["strict_false_unsupported_tags"]),
                ]
            )
            + "\n"
        )

report_lines = [
    "# logical scan diff report",
    "",
    f"- files_scanned: {summary['files_scanned']}",
    f"- sampled_rules: {summary['sampled_rules']}",
    f"- clamav_hit_total(filtered): {summary['clamav_hit_total']}",
    f"- yara_hit_total(filtered): {summary['yara_hit_total']}",
    f"- mismatch_files: {summary['mismatch_files']}",
    "",
    "## mismatch categorization",
    f"- only_clamav_total: {summary['only_clamav_total']}",
    f"- only_clamav_strict_false_total: {summary['only_clamav_strict_false_total']}",
    f"- only_clamav_non_strict_total: {summary['only_clamav_non_strict_total']}",
    f"- only_yara_total: {summary['only_yara_total']}",
    f"- files(strict_false_only): {summary['mismatch_category_files']['strict_false_only']}",
    f"- files(detection_gap): {summary['mismatch_category_files']['detection_gap']}",
    f"- files(overmatch): {summary['mismatch_category_files']['overmatch']}",
    "",
    "## mismatch examples (max 20)",
]

if summary["mismatch_examples"]:
    for item in summary["mismatch_examples"]:
        report_lines.append(
            "- "
            + item["file"]
            + " | only_clamav="
            + str(item["only_clamav"])
            + " | only_clamav_strict_false="
            + str(item["only_clamav_strict_false"])
            + " | only_clamav_non_strict="
            + str(item["only_clamav_non_strict"])
            + " | only_yara="
            + str(item["only_yara"])
            + " | strict_false_unsupported_tags="
            + str(item["strict_false_unsupported_tags"])
        )
else:
    report_lines.append("- none")

report_lines.extend(["", "## top only_clamav signatures"])
if summary["top_only_clamav"]:
    for name, count in summary["top_only_clamav"]:
        report_lines.append(f"- {name}: {count}")
else:
    report_lines.append("- none")

report_lines.extend(["", "## top only_clamav (strict_false) signatures"])
if summary["top_only_clamav_strict_false"]:
    for name, count in summary["top_only_clamav_strict_false"]:
        report_lines.append(f"- {name}: {count}")
else:
    report_lines.append("- none")

report_lines.extend(["", "## top only_clamav (non_strict) signatures"])
if summary["top_only_clamav_non_strict"]:
    for name, count in summary["top_only_clamav_non_strict"]:
        report_lines.append(f"- {name}: {count}")
else:
    report_lines.append("- none")

report_lines.extend(["", "## top strict_false unsupported tags"])
if summary["top_strict_false_unsupported_tags"]:
    for name, count in summary["top_strict_false_unsupported_tags"]:
        report_lines.append(f"- {name}: {count}")
else:
    report_lines.append("- none")

report_lines.extend(["", "## top only_yara signatures"])
if summary["top_only_yara"]:
    for name, count in summary["top_only_yara"]:
        report_lines.append(f"- {name}: {count}")
else:
    report_lines.append("- none")

report_md.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
PY

echo "scan-diff completed"
echo "run_dir: ${RUN_DIR}"
echo "report:  ${REPORT_MD}"
echo "summary: ${SUMMARY_JSON}"
echo "mismatch:${MISMATCH_TSV}"
