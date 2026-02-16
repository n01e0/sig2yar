# sig2yar

ClamAV のシグネチャ1件を YARA ルール1件へ変換するツール。

- English README: [`README.md`](./README.md)
- 実装トラッキング詳細: [`CLAMAV_SIGNATURE_SUPPORT_CHECKLIST.md`](./CLAMAV_SIGNATURE_SUPPORT_CHECKLIST.md)

## このツールがやること

`sig2yar` は ClamAV のシグネチャレコードを受け取り、対応する YARA ルールを出力する。

現在の方針は **strict-safe**:

- 同型に表現できる部分はそのまま反映
- 同型に表現できない部分は危険な近似をせず、安全側に倒す

この README のサポート率では、fallback/strict-safe 経路は **未サポート扱い** とする。

## ビルド

```bash
cargo build --bin sig2yar
```

## 使い方

```bash
sig2yar <db_type> <signature>
```

ヘルプ:

```bash
sig2yar --help
```

例（`hash`）:

```bash
sig2yar hash "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature"
```

例（`logical`）:

```bash
sig2yar logical "Foo.Bar-1;Engine:51-255,Target:1;0;41424344"
```

例（`logical` + macro-group 用 `ndb` コンテキスト）:

```bash
sig2yar logical "Foo.Bar-2;Target:1;${1-2}12$;41424344" \
  --ndb-context "D1:0:$12:626262" \
  --ndb-context "D2:0:$12:636363"
```

## ClamAV DBサポート状況（概算）

> ここは計画判断向けの概算。厳密ベンチマークではない。

| DB / ファミリ | 現在状態 | 概算サポート率（ルール単位） | 主な未実装/不足 |
|---|---|---:|---|
| `hdb`, `hsb` | 実質フルサポート | **~100%** | 現状スコープで大きな欠損なし |
| `ndb` | 強い部分サポート | **~90%** | signed/open jump境界、非canonicalな`[]` jump構造、一部runtime依存offset、予約/非対応target type |
| `ldb` | 部分対応のみ | **strict基準で~0–10%**（かなり低い） | macro完全runtime意味、`fuzzy_img` runtime意味、PCREのruntime依存flags/offset組み合わせ、観測不能なtarget description制約 |
| `mdb`, `msb`, `imp` | strictサポート未実装 | **~0%** | section-hash/import-hash系のstrict同型変換が未実装 |
| `ndu`, `idb`, `cdb`, `cfg`, `crb`, `pdb`, `wdb`, `cbc`, `ftm`, `fp`, `sfp`, `ign`, `ign2`, `hdu`, `hsu`, `ldu`, `mdu`, `msu`, `info` | parseはあるがstrict変換未実装 | **~0%** | 現状は strict-safe / fallback 経路で処理 |
