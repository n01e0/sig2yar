# sig2yar DB Support (Strict View) / DBサポート状況（厳密判定）

Last updated: 2026-02-17

## 日本語

このREADMEは、`sig2yar` が ClamAV DB をどれだけ **厳密に** 変換できるかを示す。

### 判定ポリシー（重要）

この表では次を「未サポート」に含める。

- `condition: false` / `(false)`（strict-safe）
- `clamav_unsupported` が付く
- `clamav_lowering_notes` が付く（fallback/近似/制限付きlowering）
- 変換エラー

つまり、**fallback と strict-safe は未サポート扱い**。

### 測定スナップショット

- 対象DB: `clamav-db/unpacked`（このリポジトリ内のローカル展開DB）
- レコード数:
  - 基本は「非コメント・非空行」数
  - `cbc` はファイル単位（非空payloadファイル数）
- 評価方法:
  - `target/debug/sig2yar` で各シグネチャをlower
  - 大規模DBは reservoir sampling（`hdb/hsb/mdb: 300`, `ldb/ndb: 800`）
  - それ以外は全件評価

### DB別サポート状況

| DB | Records | Evaluated | Strictly supported | Unsupported (incl. fallback/strict-safe) | Notes |
|---|---:|---:|---:|---:|---|
| hdb | 20,444 | 300 (sample) | 300 (100.0%) | 0 | hash-file signatures |
| hsb | 521,446 | 300 (sample) | 300 (100.0%) | 0 | hash-file signatures |
| mdb | 2,670,547 | 300 (sample) | 0 (0.0%) | 300 | section-hash family currently strict-safe false |
| msb | 3 | 3 | 0 (0.0%) | 3 | section-hash family currently strict-safe false |
| imp | 0 | 0 | - | - | no records in this snapshot |
| ldb | 311,662 | 800 (sample) | 0 (0.0%) | 800 | sampled rules all had fallback notes/unsupported meta |
| ndb | 101,891 | 800 (sample) | 747 (93.4%) | 78 (53 notes + 25 strict-false) | partial strict support, unsupported edges still exist |
| ndu | 4,159 | 4,159 | 0 (0.0%) | 4,159 | strict-safe false track |
| idb | 222 | 222 | 0 (0.0%) | 222 | strict-safe false track |
| cdb | 135 | 135 | 0 (0.0%) | 135 | strict-safe false track |
| cfg | 21 | 21 | 0 (0.0%) | 21 | strict-safe false track |
| crb | 30 | 30 | 0 (0.0%) | 30 | strict-safe false track |
| pdb | 263 | 263 | 0 (0.0%) | 263 | strict-safe false track |
| wdb | 185 | 185 | 0 (0.0%) | 185 | strict-safe false track |
| cbc | 85 | policy-based | 0 (0.0%) | 85 | bytecode signatures are intentionally strict-safe false |
| ftm | 268 | 268 | 0 (0.0%) | 268 | strict-safe false track |
| fp | 996 | 996 | 0 (0.0%) | 996 | strict-safe false track |
| sfp | 2 | 2 | 0 (0.0%) | 2 | strict-safe false track |
| ign | 1 | 1 | 0 (0.0%) | 1 | strict-safe false track |
| ign2 | 13 | 13 | 0 (0.0%) | 13 | strict-safe false track |
| hdu | 39 | 39 | 0 (0.0%) | 39 | strict-safe false track |
| hsu | 1 | 1 | 0 (0.0%) | 1 | strict-safe false track |
| ldu | 10,166 | 10,166 | 0 (0.0%) | 10,166 | strict-safe false track |
| mdu | 315 | 315 | 0 (0.0%) | 315 | strict-safe false track |
| msu | 1 | 1 | 0 (0.0%) | 1 | strict-safe false track |
| info | 124 | 124 | 0 (0.0%) | 124 | strict-safe false track |

### いまの結論

- 実運用上「厳密サポート」と言えるのは、現時点では **`hdb` / `hsb` と `ndb` の一部**。
- それ以外は、ポリシー上「未サポート（fallback / strict-safe含む）」として扱うべき。
- 詳細トラッキングは `CLAMAV_SIGNATURE_SUPPORT_CHECKLIST.md` を参照。

---

## English

This README summarizes how much of ClamAV DB `sig2yar` can convert in a **strict** sense.

### Classification policy (important)

In this document, the following are all treated as **unsupported**:

- `condition: false` / `(false)` (strict-safe)
- `clamav_unsupported` is present
- `clamav_lowering_notes` is present (fallback/approximation/constrained lowering)
- conversion error

So, **fallback and strict-safe are counted as unsupported**.

### Measurement snapshot

- Target DB: `clamav-db/unpacked` (local unpacked DB in this repo)
- Record counting:
  - line-based (`non-empty`, `non-comment`) for most DBs
  - file-based for `cbc` (non-empty payload files)
- Evaluation:
  - lower each signature with `target/debug/sig2yar`
  - reservoir sampling for very large DBs (`hdb/hsb/mdb: 300`, `ldb/ndb: 800`)
  - full evaluation for the rest

### Support by DB type

(Shared table above: same numbers/definitions for JP/EN.)

### Current takeaway

- Strictly-supported coverage is currently practical mainly for **`hdb` / `hsb` and part of `ndb`**.
- Everything else should be treated as unsupported under this strict policy.
- For implementation details and ongoing work, see `CLAMAV_SIGNATURE_SUPPORT_CHECKLIST.md`.
