# Tecno ファームウェアからの LUTs・アセット抽出ガイド

> 対象: Tecno Pova Curve 2 5G    
> 作成日: 2026-02-20  

このドキュメントでは、展開済みのTecnoデバイス（およびInfinixなどのTranssion系デバイス）のシステムイメージから、カメラフィルター（LUTs）、透かし、その他のアセットを抽出する手順を解説します。

> **前提**: すでに `system.img`, `product.img`, `vendor.img`, `system_ext.img` などのパーティションが展開またはマウントされており、ファイルシステムにアクセスできる状態であることを想定しています。

## ターゲットファイルの場所一覧

Tecnoデバイスにおいて、LUTや透かしが含まれる主要なファイルは以下のパーティションパスに配置されています。

| アセットの種類 | ファイル名 | 一般的なパス (パーティション内) | 含まれるデータ |
| :--- | :--- | :--- | :--- |
| **カメラアプリ** | `EngineerCamera.apk` | `product/app/EngineerCamera/` | メインのLUT、フィルター、UIリソース |
| **カメラアプリ (旧/別名)** | `Camera.apk` | `product/priv-app/Camera/` | 同上 |
| **AIエンジン** | `ImagingAiEngine.apk` | `vendor/app/ImagingAiEngine/` | AI美顔補正データ、モデルファイル |
| **ギャラリー** | `AiGallery.apk` | `system_ext/app/AiGallery/` | 編集用フィルター、空の置換フィルター |
| **透かしライブラリ** | `libTranGoldWaterMark.so` | `vendor/lib64/` | 透かし処理ロジック (Shared Library) |
| **透かしライブラリ** | `libWaterMarkProc.so` | `vendor/lib64/` | 透かし処理ロジック (Shared Library) |
| **透かし設定/画像** | `watermark` フォルダ | `vendor/etc/watermark/` | 透かしの設定JSONやリソース画像 |

---

## 手順 1: APKとライブラリの収集

まず、上記のパスを参考に必要なファイルを一箇所（例: `extracted_files`）に集めます。

```bash
# 作業用ディレクトリの作成
mkdir -p extracted_files/camera extracted_files/gallery extracted_files/watermark

# コピーコマンド例 (パスは実際の展開場所に合わせて調整してください)
# カメラ関連
cp <path_to_product>/app/EngineerCamera/EngineerCamera.apk extracted_files/camera/
cp <path_to_vendor>/app/ImagingAiEngine/ImagingAiEngine.apk extracted_files/camera/

# ギャラリー関連
cp <path_to_system_ext>/app/AiGallery/AiGallery.apk extracted_files/gallery/

# 透かし関連 (.soファイル)
cp <path_to_vendor>/lib64/libTranGoldWaterMark.so extracted_files/watermark/
cp <path_to_vendor>/lib64/libWaterMarkProc.so extracted_files/watermark/

# 透かし関連 (リソースフォルダがある場合)
cp -r <path_to_vendor>/etc/watermark extracted_files/watermark/resources
```

---

## 手順 2: APKからのアセット抽出

APKファイルは実質的にZIPファイルです。これらを解凍して、内部のアセットフォルダから目的の画像ファイルを探します。

### 1. APKの解凍
```bash
cd extracted_files/camera
# EngineerCameraを展開
unzip EngineerCamera.apk -d EngineerCamera_content
```

### 2. フィルター・LUTの探索
解凍したフォルダ内で `assets` ディレクトリを確認します。Tecnoのカメラアプリでは以下のようなフォルダ構造が一般的です。

*   **`assets/makeup_filters/`**:
    *   美顔効果用のマスク画像やLUT。
    *   例: `contrast_max.png`, `lips0000.png`, `blusher000.png`
*   **`assets/quvideo_filters/`**:
    *   動画モード用フィルター。ファイル名が16進数のハッシュ値になっていることが多いです。
*   **`assets/luts/`**:
    *   色変換テーブル (`.cube` や `.png` 形式のLUT)。
*   **`assets/sky_filters/`**:
    *   「スカイショップ」などの空の置換機能で使われる空の画像素材。
*   **`assets/watermark_svgs/`**:
    *   透かしのSVGデータが含まれる場合があります。

### 3. ファイルの整理 (例)
抽出したアセットを整理して保存します。

```bash
# 保存先ディレクトリ
mkdir -p ../../extracted_assets/makeup_filters

# makeup_filtersをコピー
cp -r EngineerCamera_content/assets/makeup_filters/* ../../extracted_assets/makeup_filters/
```

---

## 手順 3: 透かし (Watermark) の抽出と解析

Tecnoの透かし機能は、画像ファイルと設定ファイルの組み合わせで動作します。

### 設定ファイル (JSON)
`vendor/etc/watermark/` やAPKの `assets` 内に `TranssionWM.json` や `watermark.json` といったファイルがないか探します。
このファイルには、透かしの配置、サイズ、使用する画像ファイル名が記述されています。

### 画像リソース
以下の拡張子で検索をかけ、透かし画像を探します。

*   `.svg`: ベクター形式のロゴやアイコン（最近のモデルで主流）。
*   `.png`: ラスター形式のアイコン。
*   `.ttf`: 日付や場所の描画に使われるフォントファイル。


---

## 完了

これで、Tecnoデバイスのファームウェアから以下のデータを抽出できました。

1.  **LUTs / Filters**: カメラアプリやギャラリーアプリ内の `.png`, `.cube` ファイル。
2.  **Watermarks**: `vendor` パーティションやAPK内の `.svg`, `.png`, `.json` ファイル。
3.  **Fonts**: 透かし描画用の `.ttf` ファイル。

これらは `extracted_assets` フォルダに整理され、LUT適用ツールや画像編集ソフトで利用可能な状態になります。