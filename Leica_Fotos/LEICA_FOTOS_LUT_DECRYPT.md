# Leica LUT 抽出・復号手順書

> 対象: v5.8.0  
> 作成日: 2026-02-20

Leica FOTOSアプリのAPKから暗号化されたLUTファイルを抽出し、復号する手順をまとめたドキュメントです。

## 概要

Leica FOTOSアプリ内のアセットには、Leica独自のLook（LUT）が含まれていますが、AES-256-GCMで暗号化されています。
本手順では、静的解析で暗号化方式を特定し、Fridaを使用した動的解析で暗号鍵を抽出、最終的にLUTを復号して汎用的な `.cube` および `.bin` 形式に変換します。

## 必要要件

*   **PC環境**: Linux (推奨), macOS, または Windows (WSL)
*   **ツール**:
    *   `frida` (PC側クライアント)
    *   `openssl`
    *   `python3` (および `pycryptodome` ライブラリ)
    *   `adb` (Android Debug Bridge)
    *   `unzip`
*   **Android端末**: Root化済みで、`frida-server` が動作していること
*   **対象アプリ**: Leica FOTOS (`com.leica_camera.app`) 
*   **Google Play Store Link**: https://play.google.com/store/apps/details?id=com.leica_camera.app&hl=ja

## 手順

### 1. APKからのファイル抽出

APKファイルから、暗号化されたLUTファイル (`.CUBE.enc`) と、解析対象のネイティブライブラリを抽出します。

```bash
# 作業ディレクトリの作成
mkdir -p extracted_files/luts
mkdir -p extracted_libs

# APKの解凍 (ファイルパスは適宜変更してください)
unzip -q <com.leica_camera.app.apk> "assets/looks/cube/*.CUBE.enc" -d temp_extract
unzip -q <com.leica_camera.app.apk> "lib/arm64-v8a/libnative-lib.so" -d extracted_libs

# ファイルの移動
mv temp_extract/assets/looks/cube/*.CUBE.enc extracted_files/luts/
rm -rf temp_extract
```

### 2. 暗号鍵の取得 (Frida)

アプリ実行時に生成される暗号鍵をFridaを使って抽出します。

#### 2-1. スクリプトの作成

以下の内容で `dump_key.js` を作成します。

```javascript
// dump_key.js
function hookNative() {
    var libraryName = "libnative-lib.so";
    var funcName = "Java_com_leicacamera_obfuscation_NativeKeyProvider_getKey";
    
    var module = Process.findModuleByName(libraryName);
    
    if (module) {
        console.log("[+] Library found: " + module.name);
        var funcAddr = module.findExportByName(funcName);
        
        if (funcAddr) {
            Interceptor.attach(funcAddr, {
                onLeave: function(retval) {
                    if (retval.isNull()) return;
                    Java.perform(function() {
                        try {
                            var strObj = Java.cast(retval, Java.use("java.lang.String"));
                            var keyStr = strObj.toString();
                            var keyHex = "";
                            for (var i = 0; i < keyStr.length; i++) {
                                keyHex += keyStr.charCodeAt(i).toString(16).padStart(2, '0');
                            }
                            console.log("--------------------------------------------------");
                            console.log("KEY FOUND (Hex): " + keyHex);
                            console.log("--------------------------------------------------");
                            Interceptor.detachAll();
                        } catch(e) {}
                    });
                }
            });
            return true;
        }
    }
    return false;
}

var interval = setInterval(function() {
    if (hookNative()) clearInterval(interval);
}, 1000);
```

#### 2-2. スクリプトの実行

PCと端末を接続し、以下のコマンドを実行します。アプリが自動的に起動します。

```bash
frida -U -f com.leica_camera.app -l dump_key.js
```

アプリが起動したら、LUTの選択画面などに移動して鍵生成処理をトリガーします。
ログに **`KEY FOUND (Hex)`** が表示されたら成功です。

*   **特定されたKey (Hex)**: `6247567059324666593246745a584a685832567559334a356348526661325635`
    *   (Base64デコード文字列: `leica_camera_encrypt_key`)

### 3. 復号処理

取得した鍵を使用して、すべてのLUTファイルを復号します。

#### 3-1. 復号スクリプトの作成

以下のPythonスクリプト `decrypt_luts.py` を作成します。

```python
import os
import base64
from Crypto.Cipher import AES

# Fridaで取得したHexキー
KEY_HEX = "6247567059324666593246745a584a685832567559334a356348526661325635"
KEY = bytes.fromhex(KEY_HEX)

SOURCE_DIR = "extracted_files/luts"
DEST_DIR = "decrypted_luts"

if not os.path.exists(DEST_DIR):
    os.makedirs(DEST_DIR)

print(f"Decrypting LUTs from {SOURCE_DIR}...")

for filename in os.listdir(SOURCE_DIR):
    if not filename.endswith(".CUBE.enc"):
        continue
        
    filepath = os.path.join(SOURCE_DIR, filename)
    dest_path = os.path.join(DEST_DIR, filename.replace(".CUBE.enc", ".cube"))
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            
        # Base64デコード（分割されている場合があるため結合して処理）
        parts = content.split(b']')
        full_binary = b"".join([base64.b64decode(p) for p in parts if p.strip()])
        
        # IV (先頭16バイト) と Tag (末尾16バイト) の抽出
        iv = full_binary[:16]
        tag = full_binary[-16:]
        ciphertext = full_binary[16:-16]
        
        # AES-256-GCM 復号
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        
        with open(dest_path, 'wb') as f:
            f.write(decrypted)
        print(f"  [OK] {filename}")
        
    except Exception as e:
        print(f"  [FAIL] {filename}: {e}")
```

#### 3-2. スクリプトの実行

```bash
# 依存ライブラリのインストール
pip install pycryptodome

# 実行
python3 decrypt_luts.py
```

成功すると、`decrypted_luts/` ディレクトリに `.cube` ファイルが生成されます。

### 4. バイナリ形式 (.bin) への変換 (オプション)

必要に応じて、`.cube` ファイルを RGB Float32 形式のバイナリファイルに変換します。

#### 4-1. 変換スクリプトの作成

以下のPythonスクリプト `convert_to_bin.py` を作成します。

```python
import os
import struct

SOURCE_DIR = "decrypted_luts"
DEST_DIR = "converted_bins"

if not os.path.exists(DEST_DIR):
    os.makedirs(DEST_DIR)

def read_cube_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
    data = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("TITLE") or line.startswith("DOMAIN") or line.startswith("LUT_3D_SIZE"):
            continue
        parts = line.split()
        if len(parts) == 3:
            try:
                data.append((float(parts[0]), float(parts[1]), float(parts[2])))
            except ValueError: continue
    return data

for filename in os.listdir(SOURCE_DIR):
    if not filename.endswith(".cube"): continue
    
    data = read_cube_file(os.path.join(SOURCE_DIR, filename))
    dest_path = os.path.join(DEST_DIR, filename.replace(".cube", ".bin"))
    
    with open(dest_path, 'wb') as f:
        for r, g, b in data:
            f.write(struct.pack('fff', r, g, b))
    print(f"Converted {filename}")
```

#### 4-2. スクリプトの実行

```bash
python3 convert_to_bin.py
```

`converted_bins/` ディレクトリに `.bin` ファイルが生成されます。

## 技術詳細まとめ

*   **暗号化アルゴリズム**: AES-256-GCM
*   **鍵 (Key)**: `leica_camera_encrypt_key` のBase64エンコード値 (32バイト)
*   **IV**: 暗号化バイナリの先頭16バイト
*   **Tag**: 暗号化バイナリの末尾16バイト
*   **コンテナ**: Base64エンコードされたテキストファイル（`]` で分割される場合あり）
