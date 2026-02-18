# TODO (strict-safe gap backlog)

Last update: 2026-02-18

このTODOは「今は strict-safe (`false + note`) に倒している不足機能」を、
**本当に strict support に引き上げられるものから順に潰す**ための棚卸し。

方針:
- 近似で通さない（strict-safe最優先）
- 表現不能は無理に実装しない
- ただし「実装不足で strict-false になっているもの」は積極的に解消する

---

## A. LDB/logical の strict-safe ギャップ

### A1. PCRE 変換（優先度: 高）
- [x] `(?P...)` の blanket strict-false を分解し、
      **同型で落とせる subset**（例: 名前付きcaptureのみで backrefなし）を抽出して strict support 化
      - 2026-02-17: `(?P<name>...)` は許可
      - 2026-02-17: `(?P'name'...)` は `(?P<name>...)` へ同型rewriteして許可
      - 維持: `(?P=...)`（named backreference）など yara-x 非互換経路は strict-false
- [x] PCRE flags/offset の strict-false 経路を分類し、
      YARA側で同型表現可能なものを個別に support 化
      - 2026-02-17: `g` flag は strict-false から除外（同型で表現可能として許可）
      - 2026-02-17: exact offset + `r` (`10:.../r`) は `@ >= offset` 条件で strict support 化
      - 2026-02-17: absolute range + `re` (`n,m:.../re`) は bounded window（`@ >= n` かつ `@+! <= n+m`）で strict support 化
      - 2026-02-17: exact offset + `e/re` は matcher-pcre 挙動（`adjshift==0` では `e` がwindowを狭めない）に合わせて strict support 化
      - 2026-02-17: absolute range + non-`e`（`n,m:.../`）は start-window（`@ in [n, n+m]`）で strict support 化
      - 2026-02-17: relative offset（`EP/Sx/SL/SE/EOF-`）上の non-`e` + maxshift も start-window 同型で strict support 化
      - 2026-02-17: range（maxshift）上の `r/re` は `matcher-pcre.c` 同型で window 条件に落とし込み、strict-false から除外
      - 2026-02-18: A1-2は完了扱い（同型で表現不能な残件は `pcre_unsupported_flag` / `pcre_offset_*` taxonomy で strict-false維持）
- [x] trigger prefix の strict-false 経路（count/distinct/self/missing含む）を
      「同型可/不可」で再分類し、同型可だけ support 化
      - 2026-02-17: count-comparator subset（`=x`, `=x,y`, `>x`, `<x`）は strict support 化
      - 2026-02-17: distinct comparator の single-subsig subset（`0>x,y`, `0<x,y`）は strict support 化（distinct閾値は note 付きで無視）
      - 2026-02-17: strict-false維持経路（grouped distinct / self / missing / trigger parse fail / trigger expr parse fail / trigger resolved false）を `clamav_unsupported` tag で機械可読化
      - 維持: grouped distinct（`(a|b)>x,y` / `(a|b)<x,y`）と self/missing 参照は strict-false 維持

### A2. byte_comparison（優先度: 中）
- [x] non-raw little-endian / non-exact / auto-base など strict-false 系のうち、
      同型実装できるケースを切り出して support 化
      - 2026-02-17: strict subset として `width=1` を support 化
        - non-raw non-exact（`!e`）は `width=1` のとき strict support
        - non-raw little-endian は `h` base かつ `width=1` のとき strict support
      - 2026-02-18: non-raw little-endian `h` base を拡張
        - `width>1` は `exact(e)` かつ偶数幅の subset を strict support（ClamAVのLE byte-pair normalizationに同型化）
        - `width>1` かつ non-exact / odd幅 は strict-false 維持
      - 2026-02-18: offset token の strict subsetを拡張
        - plain `0` と empty token（`#...`）を ClamAV互換で offset=0 として strict support
      - 2026-02-18: auto-base (`a`) の strict subsetを拡張
        - `width<=2` は ClamAV auto-detect上 hex判定に入らないため decimal同型として strict support
        - `width>2` は strict-false 維持（`0x` prefix有無による runtime分岐を未実装）
- [x] raw size 制約（1/2/4/8以外）と幅制約のうち、
      安全に同型へ寄せられる範囲があるかを検証
      - 2026-02-18: ClamAV `matcher-byte-comp.c` 再確認の結果、binary(raw) は 1/2/4/8 以外を loaderで拒否。
        同型で追加可能な raw size は無いため、3/5/6/7/9+ は strict-false 固定を維持。
- [x] strict-false 維持経路の機械可読化（taxonomy）
      - 2026-02-17: `byte_comparison` strict-false 主要経路に `clamav_unsupported` tag を付与
      - 例: clause-count/negative/contradictory/trigger-unresolved/non-string-reference/
             non-raw(little-endian|non-exact|auto-base|decimal-hex-alpha|hex-width-over-limit|unrepresentable)/
             raw(size-unsupported|threshold-out-of-range)/format-invalid

### A3. logical expression 周辺（優先度: 中）
- [ ] `MultiGt` / `MultiLt` grouped strict-false のうち、
      distinct条件を壊さず表現できる subset の有無を調査
- [ ] macro trigger/anchor 周辺 strict-false のうち、
      runtime依存なしで確定化できる経路を追加

### A4. target description（優先度: 低）
- [ ] `Engine` / `Container` / `Intermediates` / `IconGroup1` / `IconGroup2` の strict-false について、
      standalone YARAで観測可能にする設計があるか再調査

### A5. fuzzy_img（優先度: 低）
- [ ] `fuzzy_img` strict-false の改善可能性を調査
      （standalone YARA内で同型不可なら「明確に非対象」として固定）

---

## B. NDB の strict-safe ギャップ

### B1. body/jump 構造（優先度: 中）
- [ ] signed/open/descending/over-maxdist jump strict-false のうち、
      ClamAV matcher と同型で実装可能な subset があるかを再評価
- [ ] `[]` jump の非canonical構造 strict-false のうち、
      matcher source と矛盾しない拡張余地を再評価

### B2. offset/target_type（優先度: 中）
- [ ] offset strict-false（EP/Sx/SE/SL/VI/macro系）を
      「runtime必須」と「実装不足」で分類し直す
- [x] target_type strict-false（reserved/invalid/internal+）は
      仕様上サポート対象外として明確化（実装TODOからは分離）
      - 2026-02-18: NDB-5方針として `target_type=8/13+` と invalid literal を strict-false固定で運用。
        README の support表（"reserved/unsupported target types"）と checklist（NDB-5/追記7）へ根拠を集約。

---

## C. DBタイプ単位で strict-safe のままになっている領域

### C1. strict support 化を検討する候補（優先度: 高）
- [x] `mdb` / `msb` / `imp` の strict mapping 設計と最小回帰テスト導入
      - 2026-02-17: `mdb/msb` section-hash は strict support 化（`pe.sections[*]` + `hash.{md5,sha1,sha256}`）
      - 2026-02-18: `imp` は DBタイプ分離（`sig2yar imp`）で strict support 化（`pe.is_pe` + `pe.imphash()` + optional filesize guard）

### C2. runtime依存が強いため要方針決定（優先度: 中）
- [x] `idb`, `cdb`, `crb`, `pdb`, `wdb`, `cbc`, `ftm`, `fp`, `sfp`, `ign`, `ign2`,
      `hdu`, `hsu`, `ldu`, `mdu`, `msu`, `ndu`, `cfg`, `info`
      について、
      - standalone YARA strict support 対象にするか
      - 対象外（strict-false固定）にするか
      を明文化
      - 2026-02-18: v1方針として「non-target（strict-false固定）」に分類。
        理由は README / checklist に明示（runtimeモード依存、allow/ignore override、
        外部エンジン連携、メタ更新系DBのため standalone YARA同型不可）。

---

## D. 実行計画（短期）

- [x] D1: strict-false 経路を `clamav_unsupported` / lowering note 単位で再集計し、
      「実装で潰せる順」にランキング化
      - 2026-02-17: `scripts/logical-scan-diff.sh` に track分類（A1/A2/B/C1/C2等）と actionability ranking 出力を追加
- [x] D2: P0として PCRE の同型拡張（`(?P...)` の過剰strict-false解消可能分）を段階実施
      - 2026-02-17: `(?P<name>...)` 許可 + `(?P'name'...)` rewrite許可を main へ反映
- [x] D3: P1として `mdb/msb/imp` strict mapping の最小縦切り実装（parse→lower→compile→scan回帰）
      - 2026-02-17: 第1弾として `mdb/msb` を実装
      - 2026-02-18: 第2弾として `imp` を実装（専用parser + `pe.imphash()` lower + compile/scan回帰）
- [x] D4: 対象外と判断した strict-safe 領域は README/checklist に非対象理由を明記
      - 2026-02-18: non-target一覧と理由（runtime依存/override/外部エンジン/更新メタDB）を追記
