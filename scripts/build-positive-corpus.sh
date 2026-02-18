#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DB_DIR="${CLAMAV_DB_DIR:-${ROOT_DIR}/clamav-db/unpacked}"
VALIDATION_DIR="${CLAMAV_VALIDATION_DIR:-${ROOT_DIR}/target/validation}"
OUT_DIR="${CLAMAV_POSITIVE_OUT_DIR:-${VALIDATION_DIR}/corpus-positive}"
SAMPLE_SIZE="${CLAMAV_POSITIVE_SAMPLE_SIZE:-2000}"
SEED="${CLAMAV_POSITIVE_SEED:-7331}"
WORK_DIR="${CLAMAV_POSITIVE_WORK_DIR:-${VALIDATION_DIR}/corpus-positive-build}"

if [[ ! -d "${DB_DIR}" ]]; then
  echo "ClamAV DB dir not found: ${DB_DIR}" >&2
  exit 2
fi

if [[ ! -d "${VALIDATION_DIR}" ]]; then
  echo "Validation dir not found: ${VALIDATION_DIR}" >&2
  exit 2
fi

candidate_rel_required=(
  "clamav-upstream/unit_tests/input"
  "real-corpus-exe"
)
candidate_rel_optional=(
  "clamav-upstream-decoded/clamav_hdb_scanfiles"
)

candidate_host_roots=()
candidate_scan_roots=()

for rel in "${candidate_rel_required[@]}"; do
  host_root="${VALIDATION_DIR}/${rel}"
  if [[ ! -d "${host_root}" ]]; then
    echo "Required candidate corpus root missing: ${host_root}" >&2
    exit 2
  fi
  candidate_host_roots+=("${host_root}")
  candidate_scan_roots+=("/scan/${rel}")
done

for rel in "${candidate_rel_optional[@]}"; do
  host_root="${VALIDATION_DIR}/${rel}"
  if [[ -d "${host_root}" ]]; then
    candidate_host_roots+=("${host_root}")
    candidate_scan_roots+=("/scan/${rel}")
  fi
done

mkdir -p "${WORK_DIR}"
RUN_DIR="$(mktemp -d "${WORK_DIR}/run.XXXXXX")"

SAMPLE_LDB="${RUN_DIR}/sample.ldb"
SAMPLED_NAMES="${RUN_DIR}/sample_names.txt"
CANDIDATE_ROOTS="${RUN_DIR}/candidate_roots.txt"
CLAMSCAN_OUT="${RUN_DIR}/clamscan.out"
CLAMSCAN_ERR="${RUN_DIR}/clamscan.err"
SUMMARY_JSON="${RUN_DIR}/summary.json"
MANIFEST_TSV="${RUN_DIR}/manifest.tsv"

python3 - "${DB_DIR}" "${SAMPLE_SIZE}" "${SEED}" "${SAMPLE_LDB}" "${SAMPLED_NAMES}" <<'PY'
import pathlib
import random
import sys

if len(sys.argv) != 6:
    raise SystemExit("usage: <db_dir> <sample_size> <seed> <sample_ldb_out> <sample_names_out>")

db_dir = pathlib.Path(sys.argv[1])
sample_size = max(1, int(sys.argv[2]))
seed = int(sys.argv[3])
sample_ldb_out = pathlib.Path(sys.argv[4])
sample_names_out = pathlib.Path(sys.argv[5])

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

sample_ldb_out.write_text("\n".join(reservoir) + ("\n" if reservoir else ""), encoding="utf-8")

names = set()
for line in reservoir:
    name = line.split(";", 1)[0].strip()
    if name:
        names.add(name)

sample_names_out.write_text(
    "\n".join(sorted(names)) + ("\n" if names else ""),
    encoding="utf-8",
)
PY

if [[ ! -s "${SAMPLED_NAMES}" ]]; then
  echo "No logical signature names sampled from ${DB_DIR}" >&2
  exit 1
fi

: > "${CANDIDATE_ROOTS}"
for root in "${candidate_host_roots[@]}"; do
  printf '%s\n' "${root}" >> "${CANDIDATE_ROOTS}"
done

scanned_files=0
for root in "${candidate_host_roots[@]}"; do
  count="$(find "${root}" -type f | wc -l | tr -d ' ')"
  scanned_files=$((scanned_files + count))
done

OUT_ABS="$(python3 - "${OUT_DIR}" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve())
PY
)"
VALIDATION_ABS="$(python3 - "${VALIDATION_DIR}" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve())
PY
)"

if [[ "${OUT_ABS}" == "${VALIDATION_ABS}" ]]; then
  echo "Refusing to clear validation root: ${OUT_ABS}" >&2
  exit 2
fi

case "${OUT_ABS}" in
  "${VALIDATION_ABS}"/*) ;;
  *)
    echo "Refusing unsafe output dir (must be under ${VALIDATION_ABS}): ${OUT_ABS}" >&2
    exit 2
    ;;
esac

rm -rf "${OUT_ABS}"
mkdir -p "${OUT_ABS}/files"

set +e
docker compose run --rm \
  -v "${VALIDATION_DIR}:/scan:ro" \
  --entrypoint clamscan \
  clamav \
  -r --allmatch --infected --no-summary --database /var/lib/clamav/unpacked \
  "${candidate_scan_roots[@]}" \
  >"${CLAMSCAN_OUT}" 2>"${CLAMSCAN_ERR}"
clamscan_ec=$?
set -e

if [[ "${clamscan_ec}" -gt 1 ]]; then
  echo "clamscan failed with exit code ${clamscan_ec}" >&2
  cat "${CLAMSCAN_ERR}" >&2
  exit "${clamscan_ec}"
fi

python3 - "${VALIDATION_ABS}" "${OUT_ABS}" "${SAMPLED_NAMES}" "${CLAMSCAN_OUT}" "${MANIFEST_TSV}" "${SUMMARY_JSON}" "${scanned_files}" "${CANDIDATE_ROOTS}" <<'PY'
import collections
import hashlib
import json
import pathlib
import shutil
import sys

if len(sys.argv) != 9:
    raise SystemExit(
        "usage: <validation_abs> <out_abs> <sampled_names> <clamscan_out> <manifest_tsv> <summary_json> <scanned_files> <candidate_roots>"
    )

validation_abs = pathlib.Path(sys.argv[1]).resolve()
out_abs = pathlib.Path(sys.argv[2]).resolve()
sampled_names_path = pathlib.Path(sys.argv[3])
clamscan_out_path = pathlib.Path(sys.argv[4])
manifest_tsv_path = pathlib.Path(sys.argv[5])
summary_json_path = pathlib.Path(sys.argv[6])
scanned_files = int(sys.argv[7])
candidate_roots_path = pathlib.Path(sys.argv[8])

sampled_names = {
    line.strip()
    for line in sampled_names_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if line.strip()
}

hits_by_file = collections.defaultdict(set)
all_detected_lines = 0
filtered_detected_lines = 0
all_detected_sig_counter = collections.Counter()
filtered_sig_counter = collections.Counter()

for raw in clamscan_out_path.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = raw.strip()
    if not line.endswith(" FOUND") or ": " not in line:
        continue

    all_detected_lines += 1
    file_part, sig_part = line.rsplit(": ", 1)
    sig_name_raw = sig_part[:-6]  # strip " FOUND"
    sig_name_base = (
        sig_name_raw[:-11] if sig_name_raw.endswith(".UNOFFICIAL") else sig_name_raw
    )
    all_detected_sig_counter[sig_name_raw] += 1

    if sig_name_raw in sampled_names:
        matched_sig_name = sig_name_raw
    elif sig_name_base in sampled_names:
        matched_sig_name = sig_name_base
    else:
        continue

    if file_part.startswith("/scan/"):
        rel = pathlib.PurePosixPath(file_part[6:]).as_posix()
    elif file_part == "/scan":
        rel = "."
    else:
        try:
            rel = pathlib.Path(file_part).resolve().relative_to(validation_abs).as_posix()
        except Exception:
            rel = pathlib.Path(file_part).name

    hits_by_file[rel].add(matched_sig_name)
    filtered_detected_lines += 1
    filtered_sig_counter[matched_sig_name] += 1

hash_to_out_rel = {}
manifest_rows = []
missing_sources = []

for rel in sorted(hits_by_file):
    src = (validation_abs / rel).resolve()
    try:
        src.relative_to(validation_abs)
    except ValueError:
        missing_sources.append(rel)
        continue

    if not src.is_file():
        missing_sources.append(rel)
        continue

    h = hashlib.sha256()
    with src.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    sha256 = h.hexdigest()

    out_rel = hash_to_out_rel.get(sha256)
    if out_rel is None:
        out_rel = f"files/{sha256}"
        dst = out_abs / out_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        hash_to_out_rel[sha256] = out_rel

    manifest_rows.append(
        {
            "sha256": sha256,
            "output_file": out_rel,
            "source_file": rel,
            "matched_sigs": sorted(hits_by_file[rel]),
        }
    )

manifest_tsv_path.parent.mkdir(parents=True, exist_ok=True)
with manifest_tsv_path.open("w", encoding="utf-8") as f:
    f.write("sha256\toutput_file\tsource_file\tmatched_sigs\n")
    for row in manifest_rows:
        f.write(
            "\t".join(
                [
                    row["sha256"],
                    row["output_file"],
                    row["source_file"],
                    ",".join(row["matched_sigs"]),
                ]
            )
            + "\n"
        )

summary = {
    "scanned_files": scanned_files,
    "sampled_signatures": len(sampled_names),
    "clamscan_detected_lines_total": all_detected_lines,
    "clamscan_detected_lines_filtered": filtered_detected_lines,
    "matched_files": len(manifest_rows),
    "copied_files": len(hash_to_out_rel),
    "unique_matched_sigs": len({sig for sigs in hits_by_file.values() for sig in sigs}),
    "top_detected_sigs": all_detected_sig_counter.most_common(20),
    "top_filtered_sigs": filtered_sig_counter.most_common(20),
    "candidate_roots": [
        pathlib.Path(line.strip()).as_posix()
        for line in candidate_roots_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ],
    "missing_sources": sorted(set(missing_sources)),
}

summary_json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

cp "${MANIFEST_TSV}" "${OUT_ABS}/manifest.tsv"
cp "${SUMMARY_JSON}" "${OUT_ABS}/summary.json"
cp "${SAMPLED_NAMES}" "${OUT_ABS}/sampled_sig_names.txt"

echo "positive corpus build completed"
echo "run_dir: ${RUN_DIR}"
echo "corpus_dir: ${OUT_ABS}"
echo "summary: ${OUT_ABS}/summary.json"
echo "manifest: ${OUT_ABS}/manifest.tsv"
jq -r '
  "scanned_files: \(.scanned_files)",
  "matched_files: \(.matched_files)",
  "copied_files: \(.copied_files)",
  "unique_matched_sigs: \(.unique_matched_sigs)"
' "${OUT_ABS}/summary.json"
