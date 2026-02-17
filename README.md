# sig2yar

Convert a single ClamAV signature into a YARA rule.

- Japanese README: [`README.ja.md`](./README.ja.md)
- Detailed implementation tracker: [`CLAMAV_SIGNATURE_SUPPORT_CHECKLIST.md`](./CLAMAV_SIGNATURE_SUPPORT_CHECKLIST.md)

## What this tool does

`sig2yar` takes one ClamAV signature record and emits one YARA rule.

Current design goal is **strict-safe** conversion:

- preserve semantics where possible
- when semantics cannot be represented safely, avoid risky approximation

For support reporting in this README, fallback/strict-safe paths are treated as **unsupported**.

## Build

```bash
cargo build --bin sig2yar
```

## Usage

```bash
sig2yar <db_type> <signature>
```

Show help:

```bash
sig2yar --help
```

Example (`hash`):

```bash
sig2yar hash "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature"
```

Example (`logical`):

```bash
sig2yar logical "Foo.Bar-1;Engine:51-255,Target:1;0;41424344"
```

Example (`logical` with linked NDB context for macro-group subset):

```bash
sig2yar logical "Foo.Bar-2;Target:1;${1-2}12$;41424344" \
  --ndb-context "D1:0:$12:626262" \
  --ndb-context "D2:0:$12:636363"
```

Example (`imp`, strict import-hash mapping):

```bash
sig2yar imp "d41d8cd98f00b204e9800998ecf8427e:2048:Test.Imp.EmptyImports"
```

## ClamAV DB support overview (coarse)

> This is a planning-level summary, not a formal benchmark.

| DB / family | Current status | Estimated support (rule-level) | Main missing features |
|---|---|---:|---|
| `hdb`, `hsb` | Fully supported | **~100%** | None in current scope |
| `ndb` | Partially supported (strong subset) | **~90%** | Signed/open jump edges, non-canonical square-jump forms, some runtime-dependent offset semantics, reserved/unsupported target types |
| `ldb` | Partial only | **~0–10% strict** (very low) | Full macro runtime semantics, `fuzzy_img` runtime hash behavior, PCRE runtime-dependent flags/offset combinations, non-observable target-description constraints |
| `mdb`, `msb` | Partially supported | **~70–90%** | Section-hash edge semantics validation (broader corpus) |
| `imp` | Partially supported | **~70–90%** | Broad corpus validation and edge-case semantics (`pe.imphash()` parity across toolchain/fixtures) are still pending |
| `ndu`, `idb`, `cdb`, `cfg`, `crb`, `pdb`, `wdb`, `cbc`, `ftm`, `fp`, `sfp`, `ign`, `ign2`, `hdu`, `hsu`, `ldu`, `mdu`, `msu`, `info` | Parse path exists; strict conversion intentionally non-target in v1 | **~0%** | Non-target due to runtime-mode dependency, allow/ignore override semantics, or external ClamAV engine coupling |

## Strict-safe non-target scope (v1 policy)

The following families are intentionally kept as **strict-false + note** in v1:

- Runtime mode / DB lifecycle dependent: `hdu`, `hsu`, `mdu`, `msu`, `ndu`, `ldu`, `cfg`, `info`
- Allow/ignore override semantics (not standalone detection semantics): `fp`, `sfp`, `ign`, `ign2`
- External ClamAV subsystems required: `idb`, `cdb`, `crb`, `pdb`, `wdb`, `cbc`, `ftm`

This keeps strict-safe guarantees explicit: no approximation is introduced where standalone YARA cannot be made semantically equivalent.
