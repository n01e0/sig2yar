# ClamAV Signature Support Checklist

Last update: 2026-02-13

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
- [x] `idb` (icon signatures) ※parse + strict-safe lower（`false` + note）
- [x] `cdb` (container metadata signatures) ※parse + strict-safe lower（`false` + note）
- [x] `crb` (trusted/revoked cert signatures) ※parse + strict-safe lower（`false` + note）
- [x] `pdb` (phishing protected-domain signatures) ※parse + strict-safe lower（`false` + note）
- [x] `wdb` (phishing allow-list signatures) ※parse + strict-safe lower（`false` + note）
- [x] `cbc` (bytecode) ※parse + strict-safe lower（`false` + note）

### 1.2 未サポート（parse/lower未対応）

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

- [ ] `byte_comparison` は `i`(raw, 1..8byte) と non-raw `=/>/< + exact(e)` を条件式にlower済み。`h` base の数値トークンは hex 値として解釈（例: `=10` -> `0x10`）。unsupported ケース（non-rawの非exact/LE/`a`(auto) base・表現不能値・`h` base 幅>18（`CLI_BCOMP_MAX_HEX_BLEN`）・decimal baseでhex-alpha閾値、rawの9byte+・型幅超過閾値、矛盾した multi-clause、malformed byte_comparison format）は safety false に倒す（fallbackではなく厳密化）。
- [ ] `macro` (`${min-max}id$`) は ClamAV source 準拠で **macro group id** として解釈し、未表現部分は safety false に厳密化済み（descending range / invalid format / malformed trailing `$` 欠落 / group>=32 を含む）。
  - 2026-02-12メモ: Cisco-Talos/clamav の公式テスト参照対象（`unit_tests/check_matchers.c`, `unit_tests/clamscan/regex_test.py`, `unit_tests/clamscan/fuzzy_img_hash_test.py`）および `unit_tests` 配下の `\$\{[0-9]` grep では、macro-group挙動を直接検証できるfixtureを確認できず（未発見）。
  - source根拠: `libclamav/readdb.c` (`${min-max}group$` parse, group<32)、`libclamav/matcher-ac.c` (`macro_lastmatch[group]` 依存)。**単独lowerでは runtime state 非観測のため false+note 維持**。
  - 2026-02-13 追記24: `lower_logical_signature_with_ndb_context(...)` で strict subset の macro↔ndb 連携を追加。`ndb offset=$group` かつ `target_type=0` かつ body が既存NDB strict lowerで表現可能な member のみ採用し、`subsig[idx-1]` 起点の `min-max` window 条件を生成。条件外（linkなし / 非direct anchor / non-0 target / 非表現body）は **false + note** を維持。
- [ ] `fuzzy_img` は専用ハンドリング実装済み（現状は安全側 `false` + note。malformed入力も strict-safe で `false` に統一）

### 2.3 未対応/不足

- [ ] `MultiGt` / `MultiLt` は単一subsigの occurrence count を反映済み。複合式は厳密表現不能のため **safety false + note** に統一（distinct-count近似は廃止）
- [ ] PCRE flags は `i/s/m/x/U/A` と ClamAV側 `r/e` を部分反映。maxshift without `e`・`E`・未知/legacy未対応flag は safety false へ厳密化済み。複雑条件は未対応
- [ ] PCRE trigger prefix は trigger条件＋`cli_caloff`主要offset（numeric exact/range, `*`, `EP+/-`, `Sx+`, `SL+`, `SE`, `EOF-`）を条件式に反映済み。`maxshift without e` は safety false、`VI` / macro offset（`$n$`）/不正payloadは source根拠付きで **safety false + note** を維持。さらに trigger式が loweringで `false` に解決された場合（未解決subsig参照など）は、条件を無視せず **rule条件を false + note** に厳密化済み。2026-02-13 追記25で `VI*`（`strncmp("VI",2)`）/ malformed `$...$` 解析方針を source準拠化（いずれも false+note）したため、残は runtime semantics 自体の厳密再現可否。
- [ ] hex modifier は `i/w/a` を反映済み（`w` は wide化、`wa` は ascii|wide の両許容、`iw/ia/iwa` 組合せ含む）。`f` は ClamAV fullword境界（特に wide 時の `isalnum + NUL` 判定）を現状lower未実装のため **safety false + note** に厳密化済み
- [ ] target description は `FileSize`/`EntryPoint`/`NumberOfSections` を条件反映済み。`Container`/`Intermediates` は YARA単体で観測不能のため現状は **safety false + note** で厳密化（意味反映自体は未対応）

### 2.4 ndb（extended/body）の現状

- [x] `DbType::Ndb` 追加（CLIから `ndb` 指定可能）
- [x] parser + IR + renderer 実装
- [x] bodyパターン本体のYARA化（hex/wildcard/jump/alt の基本）
- [x] offsetの主要形式をconditionへ反映（`*`, `n`, `n,m`, `EP±`, `Sx+`, `SL+`, `SE`, `EOF`）
- [x] target_typeの主要条件化（`1,2,3,4,5,6,7,9,10,11,12`）
- [x] DB feature coverageテスト（target/offset/body各カテゴリの代表サンプルを固定検証）
- [x] 複合range jump の strict 化（NDB-4）: signed jump（例: `{-15}`）/ signed-range 派生 / `[]` の非表現構文（open/signed bounds・降順・`AC_CH_MAXDIST(32)`超過）を **safety false + lowering note** に統一。`[]` は ClamAV source準拠で `[n]` / `[n-m]`（昇順かつ `<=32`）のみ通す。
- [x] target_type/offset fixture 拡張（NDB-5）: target_type の invalid literal（非numeric）/ reserved(8) / internal+ (13/14) を safety false + note で固定検証。offset は boundary representable（`1,1`）の match/non-match と、non-representable（`1,`, `EP10`, `EOF+10`, 非exec targetでの `EP+...`）を safety false + note で固定検証。
- [x] `[]` 位置構造制約の strict 化（NDB-6）: ClamAV `matcher-ac` の single-byte flank/core 構造（`ch[0]/ch[1]`）に合わせ、**表現可能形のみ**通し、それ以外（single-byte flank 不成立 / `[]` 3個以上 / 非canonical dual-`[]`）は safety false + lowering note へ統一。
  - 残ギャップ（exact）: EP/Sx/SL/SE の **実ファイル実体（PE/ELF/Mach-O）に対する再計算結果** まで含む end-to-end fixture は未整備（現在は rule文字列/strict-false/scan最小fixture中心）。

---

## 3) 次にやる順（提案 / NDB breakdown）

- [x] **NDB-1**: target_type=7（ASCII正規化）の edge-case 厳密化（uppercase を safety false 相当に弾く lower 条件 + fixture test）
- [x] **NDB-2**: target_type=3（HTML）で root/close tag の境界条件（tag terminator / order）を stricter に整理
- [x] **NDB-3**: target_type=4（MAIL）で header 行頭制約（line-start）を追加して誤検知側をさらに抑制
- [x] **NDB-4**: complex range-jump の残近似（特に `[]` / signed-range 派生）を safety false + note へ寄せる
- [x] **NDB-5**: 未対応 target_type（8/13+以外の invalid 含む）と offset 端ケースの fixture 拡張（`yara_rule`/`yara_compile`）
- [x] **NDB-6**: `[]` jump 位置構造（single-byte flank/core）を source準拠で strict 化し、非表現構造を safety false + note に統一

（継続トラック）
- [ ] `byte_comparison` の未対応領域（non-raw base の残edge-case）を厳密 lower（raw可変長 1..8・decimal-base hex-alpha strict false・non-raw auto-base strict false は対応済み）
- [ ] `macro` の未対応領域（macro group解決 / ndb連携）を反映（2026-02-13: ndb context連携の strict subset は実装済み。残は CLI経路連携・対象拡張）
- [ ] `fuzzy_img` の専用 lower
- [ ] PCRE flags / trigger prefix の残課題（複雑trigger-prefix厳密化）
- [x] `idb/cdb/crb/cbc/pdb/wdb` の優先順を暫定決定（実装コスト×件数バランス）
  - `idb`（件数: 223）※2026-02-13 parse + strict-safe lower (`false` + note) 済み
  - `cdb`（件数: 137）※2026-02-13 parse + strict-safe lower (`false` + note) 済み
  - `crb`（件数: 32）※2026-02-13 parse + strict-safe lower (`false` + note) 済み
  - `pdb`（件数: 263）※2026-02-13 parse + strict-safe lower (`false` + note) 済み
  - `wdb`（件数: 185）※2026-02-13 parse + strict-safe lower (`false` + note) 済み
  - `cbc`（件数: 8425）※2026-02-13 parse + strict-safe lower (`false` + note) 済み

---

## 4) メモ（現状観測）

- 2026-02-13 追記23: `cbc`（bytecode）の最小スライスとして `parse対象` を追加。`src/parser/cbc.rs` に bytecode payload の最小バリデーション（empty拒否・ASCII前提）を実装し、`DbType::Cbc` を CLI へ接続。
  - source根拠: docs `manual/Signatures/BytecodeSignatures.html`（`.cbc` は ASCII bytecode encoding）, `libclamav/readdb.c:2332-2387`（`cli_loadcbc` が file payload を `cli_bytecode_load` へ渡して bytecode をロード）, `libclamav/readdb.c:2422-2457`（bytecode kind / hooks 実行系の runtime 依存）。
  - `src/yara.rs` に `render/lower_cbc_signature` を追加し、bytecode VM 実行は YARA単体で厳密再現不可のため **strict-safe false + note** に統一（近似禁止）。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` / `tests/ir_pipeline.rs` / `tests/clamav_db.rs` を拡張（parser単体 + YARA compile/scan + 実DB parse/compileサンプル）。
- 2026-02-13 追記25: PCRE trigger-prefix 残課題（`VI` / macro offset `$n$`）の最小スライスとして、`src/yara.rs` の `parse_pcre_offset_spec(...)` を ClamAV `cli_caloff` 形に寄せた。
  - `VI` 判定を `base == "VI"` から `base.starts_with("VI")` に変更（`matcher.c` の `strncmp(offcpy, "VI", 2)` 準拠）。`VIjunk` のような payload 付きでも **CLI_OFF_VERSION扱いで false+note** に統一。
  - macro offset は `base.contains('$')` を macro-intent として扱い、`$<digits>$` 形でない場合は `InvalidMacroGroup` へ分類して **false+note**（`invalid format`）へ厳密化。`$<digits>$...` trailing bytes は `sscanf("$%u$")` 準拠で group decode のみ採用。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` に `VIjunk` と malformed `$foo$` の rule/compile fixture を追加。
  - 追加fixture名: `lowers_pcre_versioninfo_prefixed_payload_to_false_for_safety` / `lowers_pcre_invalid_macro_group_offset_prefix_to_false_for_safety` / `yara_rule_with_pcre_versioninfo_prefixed_payload_false_compiles_with_yara_x` / `yara_rule_with_pcre_invalid_macro_group_offset_prefix_false_compiles_with_yara_x`。
- 2026-02-13 追記24: macro 残課題（macro group解決 / ndb連携）の最小スライスとして、`src/yara.rs` に `lower_logical_signature_with_ndb_context(...)` を追加し、macro subsig の strict subset 連携を実装。
  - 連携条件（strict-safe）: `ndb.offset=$<group>` / `target_type=0` / group<32 / bodyが既存NDB strict lowerで表現可能 / macro直前subsigが direct string anchor。
  - 生成条件: `subsig[idx-1]` の start offset 基準で `{min-max}` window を `for any` 条件へ lowerし、linked ndb member body を rule string として展開（例: `$m1_0`, `$m1_1`）。
  - 非表現ケース（link無し・non-direct anchor・target!=0・non-representable body）は **false + note** を維持（近似禁止）。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` に macro↔ndb link の rule/scan fixture（match/non-match + strict-false fallback）を追加。
- 2026-02-13 追記22: `wdb` の最小スライスとして `parse対象` を追加。`src/parser/wdb.rs` に ClamAV source 準拠のバリデーション（`X/Y/M` プレフィクス、`:` 区切り、`regex_list.c:functionality_level_check` と同じ末尾 `:min-max` 形式の機能レベル抽出）を実装し、`DbType::Wdb` を CLI へ接続。
  - source根拠: docs `manual/Signatures/PhishSigs.html`（`X:RealURL:DisplayedURL[:FuncLevelSpec]`, `Y:RealURL[:FuncLevelSpec]`, `M:RealHostname:DisplayedHostname[:FuncLevelSpec]`）, `libclamav/readdb.c:1593-1610`（`cli_loadwdb` が `load_regex_matcher(..., is_allow_list_lookup=1)` を使用）, `libclamav/regex_list.c:503-519,568-576`（`X/Y/M` dispatch）, `libclamav/regex_list.c:355-395`（末尾 `:min-max` での functionality-level 取り扱い）。
  - `src/yara.rs` に `render/lower_wdb_signature` を追加し、wdb allow-list 判定は ClamAV runtime の phishing URL 抽出（RealURL/DisplayedURL concat）+ regex matcher 依存で YARA単体では厳密再現不可のため **strict-safe false + note** で明示。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` / `tests/ir_pipeline.rs` / `tests/clamav_db.rs` を拡張（parser単体 + YARA compile/scan + 実DB parse/compileサンプル）。
- 2026-02-13 追記21: `byte_comparison` non-raw base の残edge-caseとして、`h` base の `num_bytes` 上限を ClamAV source 準拠（`CLI_BCOMP_MAX_HEX_BLEN=18`）で strict-safe 化。`src/yara.rs` の `lower_textual_byte_comparison_condition(...)` で `#he19#...` のような over-limit を **false + note** に統一（近似禁止）。
  - source根拠: `libclamav/matcher-byte-comp.h`（`#define CLI_BCOMP_MAX_HEX_BLEN 18`）, `libclamav/matcher-byte-comp.c`（`CLI_BCOMP_HEX` で over-limit を malformed として拒否）。
  - `tests/yara_rule.rs`: `#he19#=1` が `condition=false` + note（`non-raw hex width 19 exceeds ClamAV limit 18`）になることを追加。
  - `tests/yara_compile.rs`: 同ケースの scan fixture が非match（0 hit）になることを追加。
- 2026-02-13 追記20: `pdb` の最小スライスとして `parse対象` を追加。`src/parser/pdb.rs` に ClamAV source 準拠のバリデーション（`R/H` プレフィクス、`:` 区切り、`regex_list.c:functionality_level_check` と同じ末尾 `:min-max` 形式の機能レベル抽出）を実装し、`DbType::Pdb` を CLI へ接続。
  - source根拠: docs `manual/Signatures/PhishSigs.html`（`R:DisplayedURL[:FuncLevelSpec]`, `H:DisplayedHostname[:FuncLevelSpec]`）, `libclamav/readdb.c:1613-1627`（`cli_loadpdb` が `load_regex_matcher` を使用）, `libclamav/regex_list.c:503-577`（`R/H` の dispatch）, `libclamav/regex_list.c:355-395`（末尾 `:min-max` での functionality-level 取り扱い）。
  - `src/yara.rs` に `render/lower_pdb_signature` を追加し、pdb の照合は ClamAV runtime の phishing engine（RealURL/DisplayedURL 抽出 + protected-domain matcher）依存で YARA単体では厳密再現不可のため **strict-safe false + note** で明示。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` / `tests/ir_pipeline.rs` / `tests/clamav_db.rs` を拡張（parser単体 + YARA compile/scan + 実DB parse/compileサンプル）。
- 2026-02-13 追記19: `crb` の最小スライスとして `parse対象` を追加。`src/parser/crb.rs` に Authenticode cert rule のバリデーション（11..13トークン、`Trusted/CodeSign/TimeSign/CertSign` の `0|1`、`Subject` 40hex必須、`Serial` 40hexまたは空、`Pubkey` 非空hex、`NotBefore` numericまたは空、`MinFL/MaxFL` numeric）を実装し、`DbType::Crb` を CLI へ接続。
  - source根拠: docs `manual/Signatures/AuthenticodeRules.html`（`Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;NotBefore;Comment[;minFL[;maxFL]]`）, `libclamav/readdb.c:3318-3322`（CRB format + `CRT_TOKENS=13`）, `libclamav/readdb.c:3358`（token count 11..13）, `libclamav/readdb.c:3389-3478`（trust/usage flags・`serial/not_before` optional）, `libclamav/readdb.c:3293-3311`（Subject/Serial を SHA1長で検証）。
  - `src/yara.rs` に `render/lower_crb_signature` を追加し、Authenticode の cert chain trust/revocation は ClamAV runtime の PE cert verification/trust store 依存で YARA単体では厳密再現不可のため **strict-safe false + note** で明示。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` / `tests/ir_pipeline.rs` / `tests/clamav_db.rs` を拡張（parser単体 + YARA compile/scan + 実DB parse/compileサンプル）。
- 2026-02-13 追記18: `cdb` の最小スライスとして `parse対象` を追加。`src/parser/cdb.rs` に ClamAV source 準拠のバリデーション（10..12トークン、`ContainerSize/FileSizeInContainer/FileSizeReal/FilePos` の `*|n|n-m`、`IsEncrypted` の `*|0|1`、`MinFL/MaxFL` numeric）を実装し、`DbType::Cdb` を CLI へ接続。
  - source根拠: docs `ContainerMetadata`（`VirusName:ContainerType:...:Res2[:MinFL[:MaxFL]]`）, `libclamav/readdb.c:3112-3137`（`CDB_TOKENS=12`, token count, optional MinFL/MaxFL）, `libclamav/readdb.c:3234-3244`（range fields + encryption flag検証）。
  - `src/yara.rs` に `render/lower_cdb_signature` を追加し、container metadata matching は ClamAV runtime の container traversal / metadata（size, encrypted flag, file position, CRC）依存で YARA単体では厳密再現不可のため **strict-safe false + note** で明示。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` / `tests/ir_pipeline.rs` / `tests/clamav_db.rs` を拡張（parser単体 + YARA compile/scan + 実DB parse/compileサンプル）。
- 2026-02-13 追記17: `fuzzy_img` 継続トラックの最小スライスとして、**malformed `fuzzy_img` を raw literal にフォールバックさせない** strict-safe 化を実施。
  - 背景: 既存実装は `parse_fuzzy_img_subsignature(...)` 成功時のみ `false + note` 化していたため、`fuzzy_img#zz...#0` のような malformed ケースが通常文字列としてlowerされる余地があった。
  - 変更: `src/yara.rs` に `looks_like_fuzzy_img_subsignature(...)` を追加し、`fuzzy_img#` prefix なのにparse失敗する場合は **`false + lowering note`** に統一（近似禁止）。
  - `tests/yara_rule.rs`: malformed fuzzy_img が `condition=false` / `strings` 空 / note（`fuzzy_img format unsupported/invalid`）になることを追加。
  - `tests/yara_compile.rs`: 同ケースの scan fixture（`xxfuzzy_img#zz...#0yy`）が非match（0 hit）になることを追加。
- 2026-02-13 追記16: `idb` の最小スライスとして `parse対象` を追加。`src/parser/idb.rs` に ClamAV source 準拠のバリデーション（4トークン、`ICON_HASH` 124桁hex、先頭サイズprefixが 16/24/32）を実装し、`DbType::Idb` を CLI へ接続。
  - source根拠: `libclamav/readdb.c:1365-1376`（token count / hash length）, `libclamav/readdb.c:1388-1397`（hex文字・size=16/24/32）, docs `LogicalSignatures`（`.idb` format: `ICONNAME:GROUP1:GROUP2:ICON_HASH`）。
  - `src/yara.rs` に `render/lower_idb_signature` を追加し、icon fuzzy matching は ClamAV runtime（icon matcher + ldb IconGroup linkage）依存で YARA単体では厳密再現不可のため **strict-safe false + note** で明示。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` / `tests/ir_pipeline.rs` / `tests/clamav_db.rs` を拡張（parser単体 + YARA compile/scan + 実DB parse/compileサンプル）。
- 2026-02-13 追記15: macro 継続トラックの最小スライスとして、malformed macro（`${6-7}0` のような trailing `$` 欠落）を raw literal にフォールバックさせず **strict-safe false + note** に統一。
  - 背景: 既存実装は `looks_like_macro_subsignature` が `${...}$` の完全形のみ検知していたため、`${...` で始まる malformed macro が raw string としてlowerされ得た。
  - 変更: `src/yara.rs` で macro判定を `${` prefix 起点に変更し、parse失敗時は既存の invalid-format 分岐へ確実に入れる。
  - `tests/yara_rule.rs`: `0|1;41414141;${6-7}0` が `($s0 or false)` になり、note（`macro subsignature format unsupported/invalid`）を持つことを追加。
  - `tests/yara_compile.rs`: 同ケースで scan fixture（`xx${6-7}0yy`）が非match（0 hit）になることを追加。
  - 検証: `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-13 追記13: `byte_comparison` non-raw base の残edge-caseとして、`a` (auto) base を strict-safe で **false + note** に統一。`src/yara.rs` の `lower_textual_byte_comparison_condition(...)` で non-raw auto-base を拒否する分岐を追加（runtime auto-detection近似を禁止）。
  - `tests/yara_rule.rs`: `#ae2#=10` で rule condition が `false` かつ note（`auto base unsupported for strict lowering`）を確認。
  - `tests/yara_compile.rs`: 同ケースで scan fixture（`xx10yy`）が非match（0 hit）になることを確認。
- 2026-02-13 追記14: hex modifier の 1スライス前進として、ClamAV `libclamav/readdb.c:cli_sigopts_handler` の `w/a/f` 挙動を再確認し、`src/yara.rs` の hex lowering を更新。
  - `w`: hex bytes を `XX 00` へ wide化して文字列化（`i` 併用時は ASCII alpha の nocase alternation を保持）。
  - `a+w`: 単一YARA hex string内で `(ascii_variant | wide_variant)` を生成し、ClamAVの `ASCII` 追加パターン読込に対応。
  - `f`: ClamAV fullword境界（`matcher-ac.c` の `isalnum` / wide時 `isalnum(byte)&&next==0`）を現状厳密表現しない方針として **false + note** へ統一。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` に wide/wa/iwa の rule文字列・compile・scan fixture と `::f` strict-false を追加。
  - 検証: `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-13 追記12: PCRE trigger-prefix strict化の最小スライスとして、trigger式が lowering で `false` に解決されたケース（未解決subsig参照など）を「constraint ignored」から **false + note** へ変更。`src/yara.rs` の `lower_pcre_trigger_condition(...)` で strict-safe を徹底。
  - `tests/yara_rule.rs`: `9/abc/`（trigger参照先なし）で rule condition が `false` かつ note を確認。
  - `tests/yara_compile.rs`: 同ケースが scan で非match（`abc` を与えても 0 hit）を確認。
  - 検証: `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-13 追記11: malformed な `byte_comparison` を raw 文字列として扱わないよう strict 化。`src/yara.rs` に `looks_like_byte_comparison(...)` を追加し、構文が byte_comparison 形なのに parse 失敗した場合は **safety false + note** に統一。
  - `tests/yara_rule.rs`: invalid threshold token（`#he2#=1G`）で strict-false note を確認。
  - `tests/yara_compile.rs`: 同ケースが scan で非match（literalとして誤マッチしない）を確認。
  - 検証: `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-13 追記10: `byte_comparison` の `h` base 閾値解釈を修正。`src/yara.rs` で比較値トークンの parse を base-aware 化し、`h` 指定時は **数字のみトークンも hex 値として解釈**（`=10` を `0x10` として扱う）。
  - `tests/yara_rule.rs` に `#he2#=10` が "10"（0x31,0x30）へ lower されることを追加。
  - `tests/yara_compile.rs` に scan fixture を追加（`"10"` は match、`"0A"` は non-match）。
  - 検証: `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-13 追記9: `MultiGt` / `MultiLt` の複合式（grouped expression）で使っていた distinct-count 近似を廃止し、`src/yara.rs` の lower を **safety false + note** に統一。単一subsigの occurrence count (`#sN`) は従来どおり反映。
  - `tests/yara_rule.rs` の grouped `MultiGt` / `MultiLt` ケースを strict-false 検証へ更新。
  - 検証: `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記8: NDB-6（`[]` positional structure strictness）として、`src/yara.rs` に `[]` 位置構造バリデーションを追加。ClamAV source（`libclamav/matcher-ac.c:2767-2836`, `libclamav/matcher-ac.c:1286-1304,1365-1381`）準拠で、**single-byte flank + core**（dual-`[]` は single-byte/core/single-byte）を満たす場合のみ lower を許可し、それ以外（single-byte flank 不成立 / `[]` 3個以上 / 非canonical dual-`[]`）は safety false + note へ統一。
  - `tests/yara_rule.rs` / `tests/yara_compile.rs` に representable dual-flank の match/non-match と strict-false note/scan を追加（source参照コメント付き）。
  - `cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記7: NDB-5（target_type/offset fixture expansion）として、`tests/yara_rule.rs` / `tests/yara_compile.rs` に以下を追加。
  - target_type: reserved(8) / internal+(13,14) / non-numeric invalid (`foo`) を **safety false + note** で固定化（ClamAV参照: `libclamav/matcher.h`, `libclamav/readdb.c`）。
  - offset: representable boundary `1,1` の match/non-match scan、non-representable `1,` / `EP10` / `EOF+10` / target_type=0 での `EP+10` を **strict false + note** で固定化（ClamAV参照: `libclamav/matcher.c:cli_caloff`）。
  - 実装側も strictness整合のため `src/yara.rs` を最小修正（`EP+/EP-` と `EOF-` 形式の厳格化、relative offset の target_type 制約チェック）。
- 2026-02-12 追記6: NDB-4（complex range-jump strictness）として、`src/yara.rs` の ndb jump lower を更新。`{-15}` のような **signed jump** は近似変換（`[0-15]`）を廃止して safety false + note 化。`[]` は ClamAV source（`libclamav/matcher-ac.c:2751-2786`, `libclamav/matcher-ac.h:32`）に合わせて `[n]` / `[n-m]`（昇順・`<=32`）のみ許可し、open/signed bounds・降順・`AC_CH_MAXDIST`超過は safety false + note 化。`tests/yara_rule.rs` / `tests/yara_compile.rs` に representable match/non-match と strict-false note 検証を追加。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
  - （解消）ClamAV `[]` の **位置制約**（single-byte flank / core pattern との構造制約）は 追記8（NDB-6）で strict 化を実装済み。
- 2026-02-12 追記5: NDB-3（target_type=4 MAIL edge-case strictness）として、secondary header 判定を **line-start 必須**（`offset==0` または直前が `\n`）へ厳密化し、既存の `secondary-header-before-separator` 条件と組み合わせて header/body ordering を strict 側に寄せた。曖昧ケースは拡張せず条件不成立に倒す方針を維持。ClamAV source 参照は `libclamav/mbox.c:1173-1183`（空行で header/body を分離）, `libclamav/mbox.c:1263-1268,1330-1391`（header行の parse）, `libclamav/mbox.c:1310-1316`（header未検出は email扱いしない）。`tests/yara_rule.rs` / `tests/yara_compile.rs` に sourceコメント付きで match/non-match（line-start header / `X-Subject:` / separator後header）を追加。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記4: NDB-2（target_type=3 HTML edge-case strictness）として、root/close tag 判定に **tag terminator (`>`/ASCII空白) 境界** を必須化し、`root-before-close` 条件でも同境界を要求するよう更新。曖昧ケースは拡張せず strict 側（条件不成立）に寄せた。ClamAV source 参照は `libclamav/scanners.c:2563-2589`（normalized HTML scan）, `libclamav/htmlnorm.c:962-1000,1229-1249`（タグトークン境界/終端タグ処理）。`tests/yara_rule.rs` / `tests/yara_compile.rs` に sourceコメント付きで match/non-match（`</html>` vs `</htmlx>`）を追加。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記3: NDB-1 として target_type=7 の strictness を更新。ClamAV `libclamav/textnorm.c`（uppercase→lowercase 正規化）に合わせ、条件を `printable + lowercase alpha 必須 + uppercase 不許可` へ寄せた。`tests/yara_rule.rs` / `tests/yara_compile.rs` に source参照コメント付き検証を追加。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 進捗: Cisco-Talos/clamav 公式fixture（`unit_tests/check_matchers.c` の pcre_testdata、`unit_tests/clamscan/regex_test.py`、`unit_tests/clamscan/fuzzy_img_hash_test.py`）を根拠に、`tests/yara_rule.rs` / `tests/yara_compile.rs` を拡張。PCRE exact offset を `==` で固定するケース、`/atre/re` + `2,6`（`r`無視+encompass window）ケース、`fuzzy_img` 非表現要素（2nd subsig併用・distance!=0）を **safety false + note** で明示検証。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。
- 2026-02-12 追記: macro-group と complex PCRE trigger-prefix の残ブロッカーを source準拠で厳密化。macro は `${min-max}group$` を group解釈し、runtime `macro_lastmatch` 依存のため safety false 化（invalid format / group>=32 も false）。PCRE trigger-prefix は `check_matchers.c` Test8/Test10・`regex_test.py` offset fixture を追加検証し、unsupported offset prefix（`EP+...`）および `$n$` macro offset を safety false + note 化。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 再通過。
- 2026-02-12 追記2: `cli_caloff` 残フォーム（`*`, `EP-`, `Sx+`, `SL+`, `SE`, `EOF-`）をPCRE trigger-prefix lowerに追加し、`tests/yara_rule.rs` / `tests/yara_compile.rs` を拡張。`SE` は ClamAV同様に section size を maxshiftへ加味し、`e`なしは safety false 維持。`VI` / `$n$` macro offset / 非数値payloadは safety false + note を維持。`cargo test --locked --test yara_rule --test yara_compile` と `cargo test --locked --all-targets` 通過。

`clamav-db/unpacked` の現物には以下拡張子が存在（2026-02-11時点）:

- `hdb hsb mdb msb ldb ndb idb cdb crb cbc pdb wdb ftm fp sfp ign ign2 hdu hsu ldu mdu msu ndu cfg info`
