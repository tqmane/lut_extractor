# Xiaomi 17 Ultra クラウドフィルター解析レポート

> 対象: Xiaomi 17 Ultra (MIUI Camera APK)  
> 作成日: 2026-02-20  
> 取得フィルター数: **73 個**（うち Leica フィルター **6 個**）

---

## 1. Leica フィルターについて

### 取得できた Leica フィルター一覧

`isLeicaFilter=true` かつ `filterType=LEICA` のフィルターは **6 種類**存在します。

| filterID | 英語名 | 中国語名 | LUT ファイル名 |
|--------|--------|--------|------|
| 2 | Leica VIV (Vivid) | 徕卡鲜艳 | `62f64b633_normal_bright.png` |
| 3 | Leica NAT (Natural) | 徕卡自然 | `ecbafbf81_normal_natural.png` |
| 4 | Leica BW NAT (Monochrome) | 徕卡单色 | `c4ff65ceb_normal_dark.png` |
| 5 | Leica BW HC (Monochrome High Contrast) | 徕卡单色HC | `4f9918023_normal_dark_high.png` |
| 6 | Leica Sepia | 徕卡漂棕 | `8c8ba4019_normal_brown.png` |
| 7 | Leica Blue | 徕卡单色蓝 | `8516839e6_normal_blue.png` |


### 注意: フィルター名の文字化けについて

JSON 内の `name` フィールドは **XOR 暗号化されたまま** 格納されているため文字化けして見えます。  
正しい名前は `nameId` フィールドをキーとして翻訳 JSON から取得します：

```
翻訳 JSON URL: https://cdn.cnbj1.fds.api.mi-img.com/camerainfra/auto-cloud-config/
                camera-filter/translation/filter/<hash>.json
```

---

## 2. クラウドフィルターの発見方法

### 背景

MIUI Camera の一部フィルターは APK に内包されず、**起動時にサーバーからダウンロード**される仕組みです。CDN の直接 URL（`cdn.cnbj1.fds.api.mi-img.com`）は認証不要で公開されていますが、**ファイル名がサーバーから提供される UUID ハッシュ付き**のため、API を呼ばずには特定できません。

### 解析フロー

```
MiuiCamera.apk
  ↓ jadx でデコンパイル
  ↓
com/xiaomi/camera/cloudfilter/FilterDataSource.java  ← エントリーポイント
  ↓
L7.b.c(module, callback)  ← Cloud Config SDK 呼び出し
  ↓
O7/d.java  ← HTTP リクエスト実装 (POST /cloud/app/getData2)
  ↓
V7/a.java  ← URL 定数 (byte 配列にエンコードされている)
  ↓
API エンドポイント特定: POST https://mcc.inf.miui.com/cloud/app/getData2
```

---

## 3. 解析の詳細手順

### Step 1: APK の抽出

```bash
# EROFS パーティションのマウント
sudo erofsfuse product_a.img /mnt/product_a

# APK の抽出
cp /mnt/product_a/priv-app/MiuiCamera/MiuiCamera.apk ./
```

### Step 2: jadx によるデコンパイル

```bash
jadx --no-res --no-debug-info --show-bad-code \
     -d /tmp/miuicamera_badcode \
     MiuiCamera.apk
```

### Step 3: CloudFilter エントリーポイントの特定

```bash
# FilterDataSource.java を探す
grep -rn "camera_app_filter_leica\|camera_app_filter_none_leica" \
     /tmp/miuicamera_badcode/sources/
# → com/xiaomi/camera/cloudfilter/FilterDataSource.java
```

**`FilterDataSource.java` での確認内容:**

```java
private static final String FILTER_LEICA_MODULE     = "camera_app_filter_leica";
private static final String FILTER_NOT_LEICA_MODULE = "camera_app_filter_none_leica";
private static final String CLOUD_ITEM_KEY          = "filter_config";
```

### Step 4: API エンドポイントの特定

`V7/a.java` の URL 定数（byte 配列で難読化）を手動デコード:

```python
bytes([104,116,116,112,115,58,47,47])   # → "https://"
bytes([109,99,99])                       # → "mcc"
bytes([46,105,110,102,46,109,105,117,105,46,99,111,109])  # → ".inf.miui.com"
# 結合 → "https://mcc.inf.miui.com"
```

`Y7/a.java` の Retrofit インターフェース:

```java
@POST("/cloud/app/getData2")
g<CloudConfigBean> a(@Body RequestBody body);
```

**確定エンドポイント:**

| 環境 | URL |
|------|-----|
| CN 本番 | `https://mcc.inf.miui.com/cloud/app/getData2` |
| 国際版 | `https://mcc-intl.inf.miui.com/cloud/app/getData2` |
| ステージング | `https://staging.mcc.inf.miui.com/cloud/app/getData2` |

### Step 5: リクエスト署名アルゴリズムの解析

`O7/d.java` より署名計算ロジックを解析:

```python
import hashlib, base64

def compute_sign(packageName, channel, version, deviceInfo_str):
    # 1. パラメータをアルファベット順にソートして結合
    params = sorted([
        ("channel",     channel),
        ("deviceInfo",  deviceInfo_str),
        ("packageName", packageName),
        ("version",     str(version))
    ])
    concat = "&".join(f"{k}={v}" for k, v in params) + "&" + packageName
    # 2. Base64 エンコード → MD5 → 大文字
    b64 = base64.b64encode(concat.encode("utf-8")).decode()
    return hashlib.md5(b64.encode("utf-8")).hexdigest().upper()
```

`deviceInfo` オブジェクト（Java `JSONObject` 挿入順に構築）:

```json
{
  "av": "<appVersion>",
  "bv": "<buildVersion>",
  "v":  "<androidApiLevel>",
  "d":  "<deviceCode>",
  "l":  "<locale>",
  "r":  "<release>",
  "t":  "stable",
  "uid": "<UUID>",
  "ihash": "<deviceHash>"
}
```

**重要:** 署名計算では `deviceInfo` を **JSON 文字列として**使い、リクエストボディでは **JSON Object として**送信します。

### Step 6: 有効な packageName の特定

```
com.miui.camera      → 400 "no such package name"  ← APK の実パッケージ名だが未登録
com.android.camera   → 200 OK ✅
com.miui.gallery     → 200 OK ✅
```

> **注意:** サーバーに登録されている packageName は APK の実際のパッケージ名とは異なります。

### Step 7: レスポンスのデコード

レスポンス構造:

```
POST /cloud/app/getData2
Response:
  data.rules[0].content  ← JSON string
    └── content.content  ← Base64 encoded Protobuf
          └── Protobuf field[1]: 暗号化 JSON bytes
          └── Protobuf field[2]: 4-byte seed (little-endian)
```

**復号アルゴリズム** (`libcloud_text_loader.so` / `TextLoader.java` より):

```python
def decrypt_content(proto_bytes):
    # 1. Protobuf をパース
    fields = parse_proto_lite(proto_bytes)
    encrypted = fields[1]          # 暗号化された JSON bytes
    seed_bytes = fields[2]         # 4 バイトの seed

    # 2. XOR キーを計算
    seed_int = int.from_bytes(seed_bytes, 'little')
    xor_key  = seed_int & 0x0F     # 下位 4 ビットのみ使用

    # 3. XOR 復号
    return bytes(b ^ xor_key for b in encrypted).decode('utf-8')
```

---

## 4. 再現スクリプト

以下のスクリプトを実行すると、クラウドフィルター一覧と LUT ファイルを取得できます。

```python
#!/usr/bin/env python3
"""
Xiaomi Camera クラウドフィルター LUT ダウンローダー
必要なもの: Python 3.8+ のみ (標準ライブラリ使用)
使用方法: python3 download_cloud_filters.py
"""
import hashlib, base64, json, urllib.request, uuid, os, collections, time

# ============================================================
# 設定
# ============================================================
OUT_DIR    = "./cloud_filters_output"
API_URL    = "https://mcc.inf.miui.com/cloud/app/getData2"
PACKAGE    = "com.android.camera"
CHANNELS   = ["camera_app_filter_leica", "camera_app_filter_none_leica"]

# ============================================================
# 署名計算
# ============================================================
def compute_sign(pkg, ch, ver, di_str):
    pairs = sorted([("channel",ch),("deviceInfo",di_str),("packageName",pkg),("version",str(ver))])
    s     = "&".join(f"{k}={v}" for k, v in pairs) + "&" + pkg
    b64   = base64.b64encode(s.encode("utf-8")).decode("utf-8")
    return hashlib.md5(b64.encode("utf-8")).hexdigest().upper()

# ============================================================
# Protobuf パーサー (varint + length-delimited fields のみ)
# ============================================================
def parse_varint(data, pos):
    result, shift = 0, 0
    while True:
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): return result, pos
        shift += 7

def parse_proto_lite(data):
    pos, fields = 0, {}
    while pos < len(data):
        tag_wire, pos = parse_varint(data, pos)
        fn = tag_wire >> 3; wt = tag_wire & 7
        if   wt == 2: length, pos = parse_varint(data, pos); fields[fn] = data[pos:pos+length]; pos += length
        elif wt == 0: _, pos = parse_varint(data, pos)
        elif wt == 1: pos += 8
        elif wt == 5: pos += 4
        else: break
    return fields

# ============================================================
# コンテンツ復号 (XOR: key = seed & 0x0F)
# ============================================================
def decrypt_content(raw_bytes):
    fields  = parse_proto_lite(raw_bytes)
    enc     = fields[1]
    seed    = int.from_bytes(fields[2], 'little')
    key     = seed & 0x0F
    return bytes(b ^ key for b in enc).decode('utf-8')

# ============================================================
# メイン処理
# ============================================================
os.makedirs(OUT_DIR, exist_ok=True)

uid     = str(uuid.uuid4())
di_dict = collections.OrderedDict([
    ("av","3.5.100.10"), ("bv","OSS.OP.OS1.6.6.6.9"), ("v","16"),
    ("d","24"), ("l","en"), ("r","stable"), ("t","stable"),
    ("uid",uid), ("ihash","")
])
di_str = json.dumps(di_dict, separators=(',',':'))

all_filters = {}

for ch in CHANNELS:
    sign = compute_sign(PACKAGE, ch, 0, di_str)
    body = {
        "sign": sign, "version": 0, "packageName": PACKAGE,
        "channel": ch, "deviceInfo": di_dict, "oaid": "", "gaid": ""
    }
    req = urllib.request.Request(
        API_URL, json.dumps(body).encode(),
        {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = json.loads(r.read())
    assert resp['code'] == 200, f"API error: {resp}"

    for rule in resp['data']['rules']:
        raw     = base64.b64decode(json.loads(rule['content'])['content'] + '==')
        decoded = json.loads(decrypt_content(raw))
        print(f"[{ch}] Got {len(decoded['filterConfig']['filterList'])} filters")
        for flt in decoded['filterConfig']['filterList']:
            fid = flt['filterId']
            all_filters[fid] = flt   # 重複排除

print(f"\nTotal unique filters: {len(all_filters)}")

# Filter LUT 画像をダウンロード
for fid, flt in sorted(all_filters.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999):
    url   = flt.get('resUrl', '')
    fname = url.split('/')[-1]
    path  = os.path.join(OUT_DIR, fname)
    if os.path.exists(path):
        print(f"  id={fid}: skip (exists) {fname}")
        continue
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"}), timeout=30) as r:
            data = r.read()
        with open(path, 'wb') as f:
            f.write(data)
        print(f"  id={fid}: OK {fname} ({len(data)//1024} KB) leica={flt['isLeicaFilter']}")
    except Exception as e:
        print(f"  id={fid}: FAIL {fname} - {e}")
    time.sleep(0.05)

print(f"\nDone. Files saved to: {OUT_DIR}/")
```

---

## 5. 取得結果サマリー

### フィルター分類

| 種別 | 件数 |
|------|------|
| **Leica フィルター** (`filterType=LEICA`) | **6** |
| 通常フィルター (`filterType=NORMAL`) | 55 |
| LUT エフェクト | 6 |
| ビデオフィルター | 9 |
| ポートレートスタイル | 3 |
| **合計** | **73** (+重複 4) = ユニーク 69 ファイル |

### Leica フィルター詳細

すべて `LutSize=512`、`renderType=LUT`、`supportDeviceList=["*"]`（全機種対応）。

```
Leica VIV  → 62f64b633_normal_bright.png    (42 KB)
Leica NAT  → ecbafbf81_normal_natural.png   (76 KB)
Leica BW NAT → c4ff65ceb_normal_dark.png    (14 KB)
Leica BW HC  → 4f9918023_normal_dark_high.png (18 KB)
Leica Sepia  → 8c8ba4019_normal_brown.png   (149 KB)
Leica Blue   → 8516839e6_normal_blue.png    (154 KB)
```

### 保存ファイル

```
lut_watermark_output/cloud_filters/
├── metadata.json                      ← フィルター完全メタデータ
├── 62f64b633_normal_bright.png        ← Leica Vivid
├── ecbafbf81_normal_natural.png       ← Leica Natural
├── c4ff65ceb_normal_dark.png          ← Leica Mono
├── 4f9918023_normal_dark_high.png     ← Leica Mono HC
├── 8c8ba4019_normal_brown.png         ← Leica Sepia
├── 8516839e6_normal_blue.png          ← Leica Blue
├── 819bc9ff6_filter_film_flowers_dream.png   ← 繁花如梦
├── ... (73 ファイル合計)
```

---

## 6. 技術的詳細

### API リクエスト仕様

```
POST https://mcc.inf.miui.com/cloud/app/getData2
Content-Type: application/json

{
  "sign":        "<MD5(Base64(sorted_params&pkg)).Upper()>",
  "version":     0,
  "packageName": "com.android.camera",
  "channel":     "camera_app_filter_leica",
  "deviceInfo":  { "av": "3.5.100.10", "bv": "...", "v": "16",
                   "d": "24", "l": "en", "r": "stable", "t": "stable",
                   "uid": "<random-uuid>", "ihash": "" },
  "oaid":        "",
  "gaid":        ""
}
```

### レスポンス復号チェーン

```
HTTP Response JSON
  └── data.rules[0].content  (JSON string)
        └── .content (JSON string)
              └── .content  (Base64 string)
                    ↓ base64_decode
                    Protobuf binary
                      field[1]: encrypted bytes  (暗号化 JSON)
                      field[2]: 4-byte seed      (XOR キーソース)
                    ↓ xor_key = seed_le_uint32 & 0x0F
                    Plaintext JSON (CloudFilterData)
                      ├── filterConfig.filterList[]  → LUT ダウンロード URL
                      ├── filterConfig.translation   → 翻訳 JSON URL
                      ├── categoryConfig
                      ├── moduleConfig
                      └── data[]  → モジュール別フィルター割り当て
```

### 暗号化ライブラリ

`libcloud_text_loader.so`（ARM64, 5,248 bytes）のネイティブ関数 `nativeLoadString(byte seed, byte[] data)` が XOR 処理を実施。seed は `protobuf.field[2]` の 4-byte リトルエンディアン整数の下位 4 ビット（`seed & 0x0F`）です。

---

## 7. 注意事項

- このプロセスは Xiaomi の内部 API を使用しています。公式ドキュメントおよびサポートはありません。
- API 仕様は予告なく変更される可能性があります。
- 取得した LUT ファイルは Xiaomi / Leica の著作物です。個人的な研究目的以外での使用はお控えください。
- `com.android.camera` という packageName はサーバー側の登録名であり、APK の実際のパッケージ名とは異なります。
