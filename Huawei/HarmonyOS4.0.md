# Huawei Gallery LUT 抽出・再現ガイド

本ドキュメントでは、Huawei Galleryアプリ（APKおよびネイティブライブラリ `.so` ファイル等）から、各種フィルターのLUT（Look Up Table）データを抽出し、動画・画像編集ソフトで利用可能な形式（`.cube` など）に変換・再現する方法について解説します。

---

## 1. 抽出対象の概要

Huaweiのフィルター機能は、実装方式により大きく2つのタイプに分かれています。

1. **Googleベースのフィルター（9種類）**
   - APK内にPNG画像（1D LUT: 256x16px）として保存されています。
   - 比較的容易に抽出および変換が可能です。

2. **Huawei独自のネイティブフィルター（38種類）**
   - フィルターの特性データ（3D LUT等）がネイティブライブラリ（`.so` ファイル）や、デバイスのシステムファイル（`.dat`）にバイナリとして直接埋め込まれています。
   - 抽出にはバイナリ解析や実機からの抽出が必要です。

---

## 2. 必要な環境・ツール

抽出作業を自身で再現・実行するには以下のツールが必要です。

- **APK解凍および逆コンパイルツール**
  - `unzip` (APKの解凍)
  - `jadx` (DEXファイルの逆コンパイル、Javaコード解析用)
- **バイナリ解析ツール**
  - `Ghidra`, `IDA Pro`, ターミナルコマンド (`hexdump`, `readelf`) など
- **スクリプト言語**
  - `Python 3` （画像処理ライブラリ `Pillow` または NumPyなど）
- **Android実機（オプション）**
  - adbツール
  - システムファイルを抽出する場合はRoot権限のあるHuaweiデバイスが推奨されます。

---

## 3. 再現手順：Googleベースのフィルター（9種類）

これらのフィルターはAPK内のリソースとして含まれています。

### ステップ1: APKの解凍
ターゲットとなるAPK（例：`base-master.apk` や `Editor-master.apk`）を展開します。
```bash
unzip base-master.apk -d extracted_apk/
```

### ステップ2: LUT画像（PNG）の特定と抽出
解凍後、フィルタープレビュー画像（1D LUT）を探します。通常以下のパスに存在します。
- `assets/filters/filtershow_fx_0000_vintage.png` などの連番ファイル。
これらは 256x16px のPNG画像で、X座標（0〜255）に対応するRGBピクセル値がそのままLUTの各階調データを表しています。

### ステップ3: 3D LUT (.cube) への変換
抽出したPNG画像をPythonスクリプトで読み込み、画像編集ソフトで読み込める汎用フォーマット（例: 33x33x33 の `.cube` 形式）に変換・マッピングします。
各ピクセルのRGB値を取得し、それを3D LUTグリッドに展開する自作コードを実行します。

---

## 4. 再現手順：Huawei独自フィルター（.so や .dat からの抽出）

残り38種類の特殊・基本フィルターは、Javaクラス（JNI）を通じて、C/C++で書かれたネイティブライブラリに処理を委譲しています。これらのデータは直接画像ファイルとしては存在しないため、以下のいずれかのアプローチでデータを抽出・生成します。

### 対象のファイル例
- `libjni_filtershow_filters.so`
- `libjni_mrc_cg_filters.so`
- `libjni_feminine_filters.so`
- システムファイル: `/system/etc/camera/filter/mixIm.dat` （または `/vendor/` 側）

---

### アプローチA: リバースエンジニアリングによる.soからのバイナリ抽出
ネイティブライブラリ（.soファイル）に直接埋め込まれたLUT配列を抜き出す方法です。

**1. .soファイルの抽出**
APKを解凍し、`lib/arm64-v8a/` などのアーキテクチャフォルダから対象の `.so` ファイルを作業フォルダにコピーします。

**2. バイナリ・シンボルの解析**
まずは `readelf` コマンド等でLUTに関連するシンボルがないか確認します。
```bash
readelf -s libjni_filtershow_filters.so | grep -i lut
```

**3. Ghidraによる静的解析とデータのエクスポート**
1. **Ghidra**（または IDA Pro）を起動し、`.so` ファイルをインポート・解析（Analyze）します。
2. DEX解析で見つけたJNI関数名（例: `Java_com_huawei_gallery_editor_filters_ImageFilterFx_nativeApplyFilterLut`）を検索し、その関数で利用されているポインタやデータ配列を追跡します。
3. 3D LUTのサイズは通常固定です（例: 33x33x33の場合、各チャンルが1Byte(0-255)なら `33 * 33 * 33 * 3 = 107,811 Bytes`、あるいはFloat配列なら `431,244 Bytes` など）。Memoryビューから対応するサイズの配列を見つけ出します。
4. 該当アドレス範囲を選択し、右クリック > **Export** > 形式を **Raw Binary** にして保存します（例: `lut_data.bin`）。

**4. CUBE形式へのパース（スクリプト化）**
抽出したバイナリデータ（`lut_data.bin`）を、Pythonを用いて標準的な `.cube` 形式に変換します。
```python
import struct

# 33x33x33のFloat32形式として想定した場合の例
size = 33
with open("lut_data.bin", "rb") as f, open("huawei_filter.cube", "w") as out:
    out.write(f"TITLE \"Huawei_Extracted\"\nLUT_3D_SIZE {size}\n")
    # RGBの順番に読み込み (RGB各4バイトFloat)
    for _ in range(size * size * size):
        r, g, b = struct.unpack('<fff', f.read(12))
        out.write(f"{r:.6f} {g:.6f} {b:.6f}\n")
```



## 5. 抽出したデータの活用方法

生成した `.cube` ファイル（例: 33x33x33 形式）は以下のクリエイティブソフト等でそのまま使用が可能です：

- **Adobe Photoshop**: 「画像」 > 「色調補正」 > 「色ルックアップテーブル」から読み込み
- **DaVinci Resolve**: カラーページのLUTブラウザにフォルダごと追加
- **Adobe Premiere Pro, Final Cut Pro, Affinity Photo** など

---

## 付録: 確認された全47種類のフィルターリスト

抽出対象となる、または実機で確認されるフィルターは計47種類です。抽出や特性サンプリングの際の目安にしてください。

### Googleベースのフィルター (9種類 - APK内PNG形式)
1. Vintage
2. Instant
3. Bleach
4. Blue Crush
5. B&W Contrast
6. Punch
7. X-Process
8. Washout
9. Washout Color

### Huawei独自フィルター (38種類 - ネイティブ/システムデータ内包)
**基本・色調フィルター (15種):**
- 早期 (日の出 / RIXI), 河豚 (FUGU), ヴァレンシア (VALENCIA), 古い映画 (LAODIANYING), 亮紅 (LIANGHONG), 雲端 (YUNDUAN), アーリーバード (EARLYBIRD), 暖洋洋 (NUANYANGYANG), 甜美人 (TIANMEIKEREN), 美食梦幻 (MEISHIMENGHUAN), 黑白 (HEIBAI), X-Pro II (XPRO2), ハドソン (HUDSON), 感情 (MYFAIR), ローファイ (LOFI)

**特殊効果フィルター (10種):**
- Huawei1〜6, 雪 (SNOW), 蛍 (FIREFLY), 花びら (PETAL), 水泡 (WATERBUBBLE)

**ダークルーム（モノクロ特化フィルム）フィルター (5種):**
- Fujifilm Neopan 100 Acros, Ilford Delta 400, Kodak T-Max 100, Kodak BW 400CN, Kodak Tri-X 400TX

**ペイント/アーティスティックフィルター (4種):**
- 水彩 (WATERCOLOR), 鉛筆 (PENCIL), 色えんぴつ (PENCIL_COLOR), クレヨン (CRAYON)

**モノクロ・エフェクトフィルター (4種):**
- モノクロ (MONO), インパクト (IMPACT), 中間調/ND (ND), ミスト (MIST)
