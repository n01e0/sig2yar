# ClamAV Signature Support Checklist

Last update: 2026-02-12

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

- [ ] `byte_comparison` は `i`(raw, 1..8byte) と non-raw `=/>/< + exact(e)` を条件式にlower済み。unsupported ケース（non-rawの非exact/LE/表現不能値・decimal baseでhex-alpha閾値、rawの9byte+・型幅超過閾値、矛盾した multi-clause）は safety false に倒す（fallbackではなく厳密化）。
- [ ] `macro` (`${min-max}id$`) は ClamAV source 準拠で **macro group id** として解釈し、未表現部分は safety false に厳密化済み（descending range / invalid format / group>=32 を含む）。
  - 2026-02-12メモ: Cisco-Talos/clamav の公式テスト参照対象（`unit_tests/check_matchers.c`, `unit_tests/clamscan/regex_test.py`, `unit_tests/clamscan/fuzzy_img_hash_test.py`）および `unit_tests` 配下の `\$\{[0-9]` grep では、macro-group挙動を直接検証できるfixtureを確認できず（未発見）。
  - source根拠: `libclamav/readdb.c` (`${min-max}group$` parse, group<32)、`libclamav/matcher-ac.c` (`macro_lastmatch[group]` 依存)。この runtime 状態は単一YARA ruleで観測不能なため、現状は **safety false + lowering note**。
- [ ] `fuzzy_img` は専用ハンドリング実装済み（現状は安全側 `false` + note）

### 2.3 未対応/不足

- [ ] `MultiGt` / `MultiLt` は単一subsigの occurrence count を反映済み。複合式は distinct-count近似で暫定対応
- [ ] PCRE flags は `i/s/m/x/U/A` と ClamAV側 `r/e` を部分反映。maxshift without `e`・`E`・未知/legacy未対応flag は safety false へ厳密化済み。複雑条件は未対応
- [ ] PCRE trigger prefix は trigger条件＋`cli_caloff`主要offset（numeric exact/range, `*`, `EP+/-`, `Sx+`, `SL+`, `SE`, `EOF-`）を条件式に反映済み。`maxshift without e` は safety false、`VI` / macro offset（`$n$`）/不正payloadは source根拠付きで **safety false + note** を維持（残: `VI`/macroの厳密表現方針）。
- [ ] hex modifier は `i` (ASCII letter nocase) を反映済み。`w/f/a` などは未対応
- [ ] target description は `FileSize`/`EntryPoint`/`NumberOfSections` を条件反映済み。`Container`/`Intermediates` は YARA単体で観測不能のため現状は **safety false + note** で厳密化（意味反映自体は未対応）

### 2.4 ndb（extended/body）の現状

- [x] `DbType::Ndb` 追加（CLIから `ndb` 指定可能）
- [x] parser + IR + renderer 実装
- [x] bodyパターン本体のYARA化（hex/wildcard/jump/alt の基本）
- [x] offsetの主要形式をconditionへ反映（`*`, `n`, `n,m`, `EP±`, `Sx+`, `SL+`, `SE`, `EOF`）
- [x] target_typeの主要条件化（`1,2,3,4,5,6,7,9,10,11,12`）
- [x] DB feature coverageテスト（target/offset/body各カテゴリの代表サンプルを固定検証）
- [ ] 複合range jump は安全側（lower失敗→condition false）へ厳密化を継続中（負数レンジ・降順レンジ、絶対offset降順rangeは safety false 化済み）。残る近似構文を継続整理
- [ ] target_type は 8/13+ を safety false 化済み。3/4 は heuristic を追加強化（HTML: root+close tag + root-before-close、MAIL: start-header + secondary-header-before-separator）。7 は **normalized-text strictness**（printable + lowercase alpha + no-uppercase）を追加済み。3 は tag terminator/order の strictness を追加済み。残は 4 edge-case（header line-start）と fixture 拡張

---

## 3) 次にやる順（提案 / NDB breakdown）

- [x] **NDB-1**: target_type=7（ASCII正規化）の edge-case 厳密化（uppercase を safety false 相当に弾く lower 条件 + fixture test）
- [x] **NDB-2**: target_type=3（HTML）で root/close tag の境界条件（tag terminator / order）を stricter に整理
- [ ] **NDB-3**: target_type=4（MAIL）で header 行頭制約（line-start）を追加して誤検知側をさらに抑制
- [ ] **NDB-4**: complex range-jump の残近似（特に `[]` / signed-range 派生）を safety false + note へ寄せる
- [ ] **NDB-5**: 未対応 target_type（8/13+以外の invalid 含む）と offset 端ケースの fixture 拡張（`yara_rule`/`yara_compile`）

（継続トラック）
- [ ] `byte_comparison` の未対応領域（non-raw base の残edge-case）を厳密 lower（raw可変長 1..8 と decimal-base hex-alpha strict false は対応済み）
- [ ] `macro` の未対応領域（macro group解決 / ndb連携）を反映
- [ ] `fuzzy_img` の専用 lower
- [ ] PCRE flags / trigger prefix の残課題（複雑trigger-prefix厳密化）
- [x] `idb/cdb/crb/cbc/pdb/wdb` の優先順を暫定決定（実装コスト×件数バランス）
  - `idb`（件数: 223）
  - `cdb`（件数: 137）
  - `crb`（件数: 32）
  - `pdb`（件数: 263）
  - `wdb`（件数: 185）
  - `cbc`（件数: 8425, bytecodeで実装難度が高いため最後）

---

## 4) メモ（現状観測）

- 2026-02-12 追記4: NDB-2（target_type=3 HTML edge-case strictness）として、root/close tag 判定に **tag terminator (`>`/ASCII空白) 境界** を必須化し、`root-before-close` 条件でも同境界を要求するよう更新。曖昧ケースは拡張せず strict 側（条件不成立）に寄せた。ClamAV source 参照は `libclamav/scanners.c:2563-2589`（normalized HTML scan）, `libclamav/htmlnorm.c:962-1000,1229-1249`（タグトークン境界/終端タグ処理）。`tests/yara_rule.rs` / `tests/yara_compile.rs` に sourceコメント付きで match/non-match（`</html>` vs `</htmlx>`）を追加。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記3: NDB-1 として target_type=7 の strictness を更新。ClamAV `libclamav/textnorm.c`（uppercase→lowercase 正規化）に合わせ、条件を `printable + lowercase alpha 必須 + uppercase 不許可` へ寄せた。`tests/yara_rule.rs` / `tests/yara_compile.rs` に source参照コメント付き検証を追加。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 進捗: Cisco-Talos/clamav 公式fixture（`unit_tests/check_matchers.c` の pcre_testdata、`unit_tests/clamscan/regex_test.py`、`unit_tests/clamscan/fuzzy_img_hash_test.py`）を根拠に、`tests/yara_rule.rs` / `tests/yara_compile.rs` を拡張。PCRE exact offset を `==` で固定するケース、`/atre/re` + `2,6`（`r`無視+encompass window）ケース、`fuzzy_img` 非表現要素（2nd subsig併用・distance!=0）を **safety false + note** で明示検証。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記: macro-group と complex PCRE trigger-prefix の残ブロッカーを source準拠で厳密化。macro は `${min-max}group$` を group解釈し、runtime `macro_lastmatch` 依存のため safety false 化（invalid format / group>=32 も false）。PCRE trigger-prefix は `check_matchers.c` Test8/Test10・`regex_test.py` offset fixture を追加検証し、unsupported offset prefix（`EP+...`）および `$n$` macro offset を safety false + note 化。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 再通過。
- 2026-02-12 追記2: `cli_caloff` 残フォーム（`*`, `EP-`, `Sx+`, `SL+`, `SE`, `EOF-`）をPCRE trigger-prefix lowerに追加し、`tests/yara_rule.rs` / `tests/yara_compile.rs` を拡張。`SE` は ClamAV同様に section size を maxshiftへ加味し、`e`なしは safety false 維持。`VI` / `$n$` macro offset / 非数値payloadは safety false + note を維持。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。

`clamav-db/unpacked` の現物には以下拡張子が存在（2026-02-11時点）:

- `hdb hsb mdb msb ldb ndb idb cdb crb cbc pdb wdb ftm fp sfp ign ign2 hdu hsu ldu mdu msu ndu cfg info`
