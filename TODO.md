# TODO (strict-safe gap backlog)

Last update: 2026-02-17

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
- [ ] PCRE flags/offset の strict-false 経路を分類し、
      YARA側で同型表現可能なものを個別に support 化
      - 2026-02-17: `g` flag は strict-false から除外（同型で表現可能として許可）
      - 2026-02-17: exact offset + `r` (`10:.../r`) は `@ >= offset` 条件で strict support 化
      - 2026-02-17: absolute range + `re` (`n,m:.../re`) は bounded window（`@ >= n` かつ `@+! <= n+m`）で strict support 化
      - 2026-02-17: exact offset + `e/re` は matcher-pcre 挙動（`adjshift==0` では `e` がwindowを狭めない）に合わせて strict support 化
- [ ] trigger prefix の strict-false 経路（count/distinct/self/missing含む）を
      「同型可/不可」で再分類し、同型可だけ support 化

### A2. byte_comparison（優先度: 中）
- [ ] non-raw little-endian / non-exact / auto-base など strict-false 系のうち、
      同型実装できるケースを切り出して support 化
- [ ] raw size 制約（1/2/4/8以外）と幅制約のうち、
      安全に同型へ寄せられる範囲があるかを検証

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
- [ ] target_type strict-false（reserved/invalid/internal+）は
      仕様上サポート対象外として明確化（実装TODOからは分離）

---

## C. DBタイプ単位で strict-safe のままになっている領域

### C1. strict support 化を検討する候補（優先度: 高）
- [ ] `mdb` / `msb` / `imp` の strict mapping 設計と最小回帰テスト導入

### C2. runtime依存が強いため要方針決定（優先度: 中）
- [ ] `idb`, `cdb`, `crb`, `pdb`, `wdb`, `cbc`, `ftm`, `fp`, `sfp`, `ign`, `ign2`,
      `hdu`, `hsu`, `ldu`, `mdu`, `msu`, `ndu`, `cfg`, `info`
      について、
      - standalone YARA strict support 対象にするか
      - 対象外（strict-false固定）にするか
      を明文化

---

## D. 実行計画（短期）

- [ ] D1: strict-false 経路を `clamav_unsupported` / lowering note 単位で再集計し、
      「実装で潰せる順」にランキング化
- [x] D2: P0として PCRE の同型拡張（`(?P...)` の過剰strict-false解消可能分）を段階実施
      - 2026-02-17: `(?P<name>...)` 許可 + `(?P'name'...)` rewrite許可を main へ反映
- [ ] D3: P1として `mdb/msb/imp` strict mapping の最小縦切り実装（parse→lower→compile→scan回帰）
- [ ] D4: 対象外と判断した strict-safe 領域は README/checklist に非対象理由を明記
