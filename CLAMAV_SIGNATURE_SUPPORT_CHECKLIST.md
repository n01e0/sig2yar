# ClamAV Signature Support Checklist

Last update: 2026-02-11

このチェックリストは「sig2yarでどのClamAVシグネチャタイプをサポートできていて、どこが未対応か」を管理するためのメモ。

---

## 1) トップレベルDBタイプ（拡張子）

### 1.1 現在サポート済み（少なくとも parse 対象）

- [x] `hdb` (hash)
- [x] `hsb` (hash)
- [x] `mdb` (hash)
- [x] `msb` (hash)
- [x] `imp` (hash)
- [x] `ldb` (logical)
- [x] `ndb` (extended/body signatures) ※parse + 実用lower（近似あり）

### 1.2 未サポート（parse/lower未対応）

- [ ] `idb`
- [ ] `cdb`
- [ ] `crb`
- [ ] `cbc` (bytecode)
- [ ] `pdb` (phishing)
- [ ] `wdb` (phishing)
- [ ] `ftm`
- [ ] `fp` / `sfp` (false positive related)
- [ ] `ign` / `ign2` (ignore lists)

### 1.3 更新/差分系ファイル（取り込み方針未整理）

- [ ] `hdu` / `hsu`
- [ ] `ldu`
- [ ] `mdu` / `msu`
- [ ] `ndu`
- [ ] `cfg` / `info` （シグネチャ本体ではないので扱い定義が必要）

---

## 2) ldb（logical）内部要素のサポート状況

### 2.1 変換できるもの

- [x] hex subsig -> YARA hex string
- [x] raw subsig -> YARA text string
- [x] pcre-like subsig -> YARA regex string（基本）
- [x] logical condition: `&`, `|`, `=`, `>`, `<`, `=min,max`

### 2.2 近似/暫定対応（要改善）

- [ ] `byte_comparison` は `i`(raw, 1/2/4/8byte) と non-raw `= + exact(e)` を条件式にlower済み。non-rawの`>/<`や非exactなどは fallback
- [ ] `macro` (`${min-max}id$`) は位置関係条件にlower済み（macro group意味の厳密反映は未完）
- [ ] `fuzzy_img` は literal fallback

### 2.3 未対応/不足

- [ ] `MultiGt` / `MultiLt` は単一subsigの occurrence count を反映済み。複合式は distinct-count近似で暫定対応
- [ ] PCRE flags は `i/s/m/x/A` と ClamAV側 `r/e` を部分反映。`E/U` などは未対応
- [ ] PCRE trigger prefix は trigger条件＋offset制約を条件式に反映済み（複雑ケースの厳密化は未完）
- [ ] hex modifier は `i` (ASCII letter nocase) を反映済み。`w/f/a` などは未対応
- [ ] target description は `FileSize`/`EntryPoint`/`NumberOfSections` を条件反映済み（Container/Intermediates等は未対応）

### 2.4 ndb（extended/body）の現状

- [x] `DbType::Ndb` 追加（CLIから `ndb` 指定可能）
- [x] parser + IR + renderer 実装
- [x] bodyパターン本体のYARA化（hex/wildcard/jump/alt の基本）
- [x] offsetの主要形式をconditionへ反映（`*`, `n`, `n,m`, `EP±`, `Sx+`, `SL+`, `SE`, `EOF`）
- [x] target_typeの主要条件化（`1,2,3,4,5,6,7,9,10,11,12`）
- [x] DB feature coverageテスト（target/offset/body各カテゴリの代表サンプルを固定検証）
- [ ] 一部構文の近似（例: 負数を含む複合range jump）を厳密化
- [ ] target_type は 8/13+ を safety false で条件化済み。残は 3/4/7 heuristic の厳密化

---

## 3) 次にやる順（提案）

1. [ ] `ndb` 近似の厳密化（target_type 3,4,7 heuristic / 未対応type / 複合range jump）
2. [ ] `byte_comparison` の未対応領域（non-raw base / rawの可変長）を厳密 lower
3. [ ] `macro` の未対応領域（macro group解決 / ndb連携）を反映
4. [ ] `fuzzy_img` の専用 lower
5. [ ] PCRE flags / trigger prefix の残課題（`E/U`, maxshift厳密意味）
6. [ ] `idb/cdb/crb/cbc/pdb/wdb` の優先順決め

---

## 4) メモ（現状観測）

`clamav-db/unpacked` の現物には以下拡張子が存在（2026-02-11時点）:

- `hdb hsb mdb msb ldb ndb idb cdb crb cbc pdb wdb ftm fp sfp ign ign2 hdu hsu ldu mdu msu ndu cfg info`
