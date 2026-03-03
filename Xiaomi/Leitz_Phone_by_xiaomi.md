# Xiaomi 17 Ultra — Leica M3 / M9 LUT 抽出手順

> 対象: Xiaomi 17 Ultra / Leica Leitzphone powered by Xiaomi   
> 作成日: 2026-03-03  

Xiaomi 17 Ultra の HyperOS ファームウェアから、Leica Essential Mode (M3/M9) で使われる 3D LUT を抽出し、HALD CLUT PNG に変換するまでの全手順。

---

## 目次

1. [必要なツールのインストール](#1-必要なツールのインストール)
2. [ファームウェアの展開](#2-ファームウェアの展開)
3. [ODM パーティションのマウント](#3-odm-パーティションのマウント)
4. [バイナリファイルの確認](#4-バイナリファイルの確認)
5. [M9 LUT の抽出 (leica_filter_param_m9_snapshot.bin)](#5-m9-lut-の抽出)
6. [M3 LUT の解析 (leica_filter_param_m3.bin)](#6-m3-lut-の解析)
7. [Leica Monopan チャンネルミックスの逆解析](#7-leica-monopan-チャンネルミックスの逆解析)
8. [M9+Monopan 合成 B&W LUT の生成](#8-m9monopan-合成-bw-lut-の生成)
9. [出力ファイル一覧](#9-出力ファイル一覧)

---

## 1. 必要なツールのインストール

```bash
# EROFS パーティション展開ツール
sudo apt install erofs-utils  # erofsfuse が含まれる

# Python パッケージ
pip install pillow scipy pycryptodome --break-system-packages
```

---

## 2. ファームウェアの展開

ファームウェアの `payload.bin` から各パーティションイメージを取り出す。

```bash
# payload_dumper を使用（https://github.com/vm03/payload_dumper）
python3 payload_dumper.py payload.bin --out /tmp/lp_out_all/

# 展開されるファイル例:
#   /tmp/lp_out_all/odm_a.img
#   /tmp/lp_out_all/product_a.img
#   /tmp/lp_out_all/system_a.img  ...
```

---

## 3. ODM パーティションのマウント

`odm_a.img` は EROFS 形式。`erofsfuse` で読み取り専用マウントする。

```bash
mkdir -p /tmp/odm_mount
erofsfuse /tmp/lp_out_all/odm_a.img /tmp/odm_mount

# 確認
ls /tmp/odm_mount/etc/camera/
# → leica_filter_param_m3.bin
# → leica_filter_param_m9_snapshot.bin
# → leica_filter_param_m9_preview.bin
# → leica_filter_param.bin  (ベース Leica LUT)
# → mialgo_monopan_cl.bin   (OpenCL シェーダー)
# → xiaomi/legendmonopansnapshot.json  (M3 パイプライン定義)
# → xiaomi/legendsnapshot.json         (M9 パイプライン定義)
```

---

## 4. バイナリファイルの確認

### ファイル一覧とサイズ

| ファイル | サイズ | 内容 |
|---|---|---|
| `leica_filter_param_m9_snapshot.bin` | 約 1.7 MB | M9 スナップショット用 114 LUT |
| `leica_filter_param_m9_preview.bin` | 約 1.7 MB | M9 プレビュー用 114 LUT |
| `leica_filter_param_m3.bin` | 約 91 KB | M3 Monopan 用 6 LUT |
| `leica_filter_param.bin` | 約 1.7 MB | ベース Leica 114 LUT |
| `mialgo_monopan_cl.bin` | 約 78 KB | M3 B&W 変換 OpenCL バイナリ |

### バイナリフォーマット解析

すべての `leica_filter_param*.bin` は共通フォーマット：

```
[ヘッダー 32 bytes]
  u16: num_dim          (M9=3, M3=6)
  u16 × num_dim: dim_sizes
  u16: max_input        (= 1024)
  u16: lut_pool_offset  (= 4096)
  u16: lut3d_size       (= 17)
  u16: num_scenes
  u16 × num_scenes: scene_sizes

[メタデータ 4×256 bytes]
  4 本の ASCII 文字列 (dim_name, type, range, timestamp)

[トリガーテーブル offset 1524 〜 4096]
  シーン × 輝度 × 色温度 → LUT インデックス のマッピング

[LUT プール offset 4096 〜]
  各 LUT = 17³ × 3 bytes = 14739 bytes
  インデックス順: [B_in][G_in][R_in] = [B_out, G_out, R_out] (uint8)
```

---

## 5. M9 LUT の抽出

### 5-1. トリガーテーブルのパース

```python
import struct, json
import numpy as np

BIN = 'leica_filter_param_m9_snapshot.bin'
with open(BIN, 'rb') as f:
    data = f.read()

# ヘッダー解析
num_dim   = struct.unpack_from('<H', data, 0)[0]   # 3
dim_sizes = [struct.unpack_from('<H', data, 2+i*2)[0] for i in range(num_dim)]
lut3d_size = struct.unpack_from('<H', data, 2+num_dim*2+4)[0]  # 17
num_scenes = struct.unpack_from('<H', data, 2+num_dim*2+6)[0]  # 5
scene_sizes = [struct.unpack_from('<H', data, 2+num_dim*2+8+i*2)[0] for i in range(num_scenes)]

LUT_POOL = 4096
LUT_SIZE = lut3d_size**3 * 3  # 14739 bytes

# トリガーテーブル: シーン毎に (lux下限, lux上限, 色温度範囲, LUT番号) を保持
trig_start = 32 + 4 * 256  # 1056
trigger_data = data[trig_start:LUT_POOL]

# シーン名 (num_dim=3 → 3次元 scene/lux/CCT)
scenes = ['common', 'portrait', 'plants', 'food', 'sunrise_sunset']
```

### 5-2. 全 114 LUT を HALD CLUT PNG に変換

HALD CLUT Level 8 = 512×512 ピクセルの PNG。
17³ グリッドを 64³ にトリリニア補間してから配置する。

```python
from pathlib import Path
from PIL import Image
from scipy.ndimage import map_coordinates

HALD_LEVEL = 8   # 8×8 ブロック = 64 スライス
DIM = 64

def lut17_to_hald(lut17):
    """17³ LUT → 512×512 HALD Level-8 PNG 配列"""
    coords = np.linspace(0, 16, DIM)
    b_c, g_c, r_c = np.meshgrid(coords, coords, coords, indexing='ij')

    # トリリニア補間で 64³ に拡大
    lut64 = np.stack([
        map_coordinates(lut17[:,:,:,ch].astype(float), [b_c,g_c,r_c], order=1)
        for ch in range(3)
    ], axis=-1).clip(0,255).astype(np.uint8)

    # HALD Level-8 配置: ピクセル(x,y) → r=x%64, g=y%64, b=(y//64)*8+(x//64)
    img = np.zeros((512, 512, 3), dtype=np.uint8)
    for b in range(DIM):
        bx, by = b % HALD_LEVEL, b // HALD_LEVEL
        img[by*64:(by+1)*64, bx*64:(bx+1)*64] = lut64[b]
    return img

out_dir = Path('firmware/m9_luts/snapshot')
out_dir.mkdir(parents=True, exist_ok=True)

for idx in range(114):
    offset = LUT_POOL + idx * LUT_SIZE
    lut17 = np.frombuffer(data[offset:offset+LUT_SIZE], dtype=np.uint8) \
              .reshape(17,17,17,3).copy()
    img_arr = lut17_to_hald(lut17)
    Image.fromarray(img_arr).save(out_dir / f'lut_{idx:03d}.png')
```

### 5-3. ユニーク LUT の選定

114 枚のうち実質ユニークなのは **8 枚** のみ（シーン種別は LUT に影響せず、輝度×色温度のみが変化）。

```python
# 全 LUT の配列をロードして重複チェック
luts = []
for idx in range(114):
    offset = LUT_POOL + idx * LUT_SIZE
    luts.append(np.frombuffer(data[offset:offset+LUT_SIZE], dtype=np.uint8).copy())

unique_indices = []
seen = []
for i, lut in enumerate(luts):
    if not any(np.array_equal(lut, s) for s in seen):
        seen.append(lut)
        unique_indices.append(i)

print(f'ユニーク LUT: {len(unique_indices)} 枚 → indices {unique_indices}')
# → [0, 2, 3, 4, 8, 9, 10, 12]  (8 枚)
```

film_sims に収録した 7 枚（lut_012 は identity のため除外）と名称対応:

| ファイル名 | LUT index | 条件 |
|---|---|---|
| `m9_warm_low_light.png` | 000 | 低輝度 + タングステン/暖色 |
| `m9_tungsten_a.png` | 002 | 中輝度 + タングステン A |
| `m9_tungsten_b.png` | 003 | 中輝度 + タングステン B |
| `m9_studio_mixed.png` | 004 | スタジオ混合光 |
| `m9_fluorescent.png` | 008 | 蛍光灯 |
| `m9_warm_neutral.png` | 009 | 中間色温度 |
| `m9_cool_daylight.png` | 010 | 昼光 / 高色温度 |

---

## 6. M3 LUT の解析

### 6-1. バイナリの読み込みと確認

```python
BIN_M3 = 'leica_filter_param_m3.bin'
with open(BIN_M3, 'rb') as f:
    data_m3 = f.read()

# ヘッダー確認
# num_dim=6, dim_sizes=[78,78,78,78,78,78], lut3d_size=17, num_scenes=5, num_luts=6
```

### 6-2. M3 LUT の内容確認（チャンネルスワップ）

```python
lut3d = np.frombuffer(data_m3[4096:4096+17**3*3], dtype=np.uint8).reshape(17,17,17,3)
# lut3d[b_in, g_in, r_in] = [B_out, G_out, R_out]

# 変換パターンの確認
errors = 0
for b in range(17):
    for g in range(17):
        for r in range(17):
            entry = lut3d[b, g, r]
            # 仮説: out_B = in_R, out_G = in_G, out_R = in_B (B↔R スワップ)
            if abs(int(entry[0]) - min(r*16,255)) > 1 or \
               abs(int(entry[1]) - min(g*16,255)) > 1 or \
               abs(int(entry[2]) - min(b*16,255)) > 1:
                errors += 1

print(f'B↔R スワップ仮説のエラー数: {errors}')  # → 0 (完全一致)
```

**結論:** M3 の LUT は 6 枚全て同一で、B↔R チャンネルスワップのみ行う。
カメラパイプライン内の BGR/RGB 順序補正のための処理であり、
**実際の B&W 変換は `mialgo_monopan_cl.bin`（OpenCL シェーダー）が担う。**

### 6-3. M3 LUT を HALD CLUT PNG に変換（参考用）

```python
out_dir_m3 = Path('firmware/m3_luts')
out_dir_m3.mkdir(parents=True, exist_ok=True)

for idx in range(6):
    offset = 4096 + idx * 17**3 * 3
    lut17 = np.frombuffer(data_m3[offset:offset+17**3*3], dtype=np.uint8) \
              .reshape(17,17,17,3).copy()
    img_arr = lut17_to_hald(lut17)
    Image.fromarray(img_arr).save(out_dir_m3 / f'lut_{idx:03d}.png')
```

---

## 7. Leica Monopan チャンネルミックスの逆解析

M3 モードの実際の B&W 変換係数を `libmialgo_monopan.so` から取得する。

### 7-1. .so ファイルから float 係数を探す

```python
import struct

with open('libmialgo_monopan.so', 'rb') as f:
    so_data = f.read()

# 合計が ~1.0 になる float3 トリプレットを探す
results = []
for i in range(0, len(so_data)-12, 4):
    v1, v2, v3 = [struct.unpack_from('<f', so_data, i+j*4)[0] for j in range(3)]
    if all(0.05 < v < 1.0 for v in [v1,v2,v3]) and 0.99 < v1+v2+v3 < 1.01:
        results.append((i, v1, v2, v3))

for offset, v1, v2, v3 in results:
    print(f'0x{offset:08x}: {v1:.5f} {v2:.5f} {v3:.5f}  sum={v1+v2+v3:.4f}')
# → 0x003e2324: 0.14617  0.41340  0.43708  (BGR 順で格納)
```

### 7-2. 係数の解釈

オフセット `0x3e2324` に BGR 順で格納された Leica Monopan チャンネルミックス係数:

| チャンネル | 係数 | 意味 |
|---|---|---|
| **R** | **0.43708** | 赤を最も強調 |
| **G** | **0.41340** | 緑も強く |
| **B** | **0.14617** | 青は抑制 |

これは **オレンジフィルター的な効果**（空は暗く、肌や木は明るく）で、
Leica M9 フィルムの銀塩モノクロに近い特性を持つ。

参考：標準的な変換係数との比較
| 方式 | R | G | B |
|---|---|---|---|
| **Leica Monopan** | **0.437** | **0.413** | **0.146** |
| BT.709 (sRGB 輝度) | 0.213 | 0.715 | 0.072 |
| BT.601 (旧テレビ) | 0.299 | 0.587 | 0.114 |

### 7-3. Leica Monopan B&W LUT の生成

```python
W_R, W_G, W_B = 0.43708, 0.41340, 0.14617

def make_monopan_lut():
    """Leica Monopan 係数による B&W 変換 HALD CLUT を生成"""
    idx = np.arange(64, dtype=np.float32) / 63.0
    r_c, g_c, b_c = np.meshgrid(idx, idx, idx, indexing='ij')
    gray = (W_R * r_c + W_G * g_c + W_B * b_c).clip(0,1)
    gray_bgr = np.transpose(gray, (2,1,0))  # [R,G,B] → [B,G,R]
    gray_u8 = (gray_bgr * 255).astype(np.uint8)

    img = np.zeros((512,512,3), dtype=np.uint8)
    for b in range(64):
        bx, by = b%8, b//8
        for g in range(64):
            for r in range(64):
                v = gray_u8[b,g,r]
                img[by*64+g, bx*64+r] = [v,v,v]
    return img

Image.fromarray(make_monopan_lut()).save('firmware/m3_luts/leica_monopan.png')
```

---

## 8. M9+Monopan 合成 B&W LUT の生成

M9 カラーグレーディング → Leica Monopan B&W の 2 段階処理を 1 枚の LUT に合成。

```python
def parse_hald(img_arr):
    """512×512 HALD Level-8 PNG → 64³ LUT 配列 [B,G,R,ch]"""
    lut = np.zeros((64,64,64,3), dtype=np.uint8)
    for b in range(64):
        bx, by = b%8, b//8
        lut[b] = img_arr[by*64:(by+1)*64, bx*64:(bx+1)*64]
    return lut

def make_hald(lut):
    """64³ LUT [B,G,R,ch] → 512×512 HALD Level-8 配列"""
    img = np.zeros((512,512,3), dtype=np.uint8)
    for b in range(64):
        bx, by = b%8, b//8
        img[by*64:(by+1)*64, bx*64:(bx+1)*64] = lut[b]
    return img

out_dir = Path('firmware/m9_monopan_luts')
out_dir.mkdir(parents=True, exist_ok=True)

m9_luts = [
    'm9_cool_daylight.png',
    'm9_tungsten_indoor.png',
    'm9_daylight_outdoor.png',
    'm9_warm_tungsten_classic.png',
    'm9_mixed_light.png',
]

for fname in m9_luts:
    # M9 LUT を読み込み
    img = np.array(Image.open(f'firmware/m9_luts/{fname}').convert('RGB'))
    lut_m9 = parse_hald(img)

    # M9 出力に Leica Monopan を適用
    R = lut_m9[:,:,:,0].astype(float)
    G = lut_m9[:,:,:,1].astype(float)
    B = lut_m9[:,:,:,2].astype(float)
    gray = (W_R*R + W_G*G + W_B*B).clip(0,255).astype(np.uint8)

    # B&W LUT を作成・保存
    lut_bw = np.stack([gray, gray, gray], axis=-1)
    out_name = fname.replace('m9_', 'm9_mono_')
    Image.fromarray(make_hald(lut_bw)).save(out_dir / out_name)
    print(f'生成: {out_name}')
```

### 合成 LUT 一覧

| ファイル名 | 元 M9 LUT | 特性 |
|---|---|---|
| `m9_mono_cool_daylight.png` | m9_cool_daylight | 昼光 + Leica B&W |
| `m9_mono_tungsten_indoor.png` | m9_tungsten_indoor | タングステン室内 + Leica B&W |
| `m9_mono_daylight_outdoor.png` | m9_daylight_outdoor | 屋外昼光 + Leica B&W |
| `m9_mono_warm_tungsten_classic.png` | m9_warm_tungsten_classic | 暖色タングステン + Leica B&W |
| `m9_mono_mixed_light.png` | m9_mixed_light | 混合光 + Leica B&W |

---

## 9. 出力ファイル一覧

```
firmware/
├── leica_params/
│   ├── leica_filter_param_m9_snapshot.bin   # 元バイナリ (M9 snapshot)
│   ├── leica_filter_param_m9_preview.bin    # 元バイナリ (M9 preview)
│   ├── leica_filter_param_m3.bin            # 元バイナリ (M3)
│   ├── legendsnapshot.json                  # M9 カメラパイプライン定義
│   └── legendmonopansnapshot.json           # M3 カメラパイプライン定義
│
├── m9_luts/
│   ├── snapshot/lut_000〜113.png  # 全 114 LUT (512×512 HALD CLUT PNG)
│   ├── preview/lut_000〜113.png   # プレビュー用 114 LUT
│   ├── trigger_table.json          # シーン×輝度×CCT → LUT番号 マッピング
│   ├── m9_cool_daylight.png        # 代表的な 5 枚 (命名済み)
│   ├── m9_tungsten_indoor.png
│   ├── m9_daylight_outdoor.png
│   ├── m9_warm_tungsten_classic.png
│   └── m9_mixed_light.png
│
├── m3_luts/
│   ├── lut_000〜005.png     # M3 の 6 LUT (全て同一・B↔R スワップ)
│   └── leica_monopan.png    # Leica Monopan B&W 変換 LUT (係数から生成)
│
└── m9_monopan_luts/
    ├── m9_mono_cool_daylight.png
    ├── m9_mono_tungsten_indoor.png
    ├── m9_mono_daylight_outdoor.png
    ├── m9_mono_warm_tungsten_classic.png
    └── m9_mono_mixed_light.png

~/git/film_sims/app/src/main/assets_raw/luts/Xiaomi/
├── leica_m9/       # M9 カラー LUT 7 枚
└── leica_m3/       # M3 B&W LUT 10 枚 (monochrome 系 4 + monopan 1 + m9_mono 5)
```

---

## 補足: なぜ M3 の B&W は LUT でなく OpenCL か

カメラパイプライン (`legendmonopansnapshot.json`) を見ると:

1. `offcamb2y` — RAW → YUV 変換（**ここで ISP が B&W 化**）
2. `mialgoallinone` — AI 処理（ノイズ除去など）
3. `mileicafilter` — `leica_filter_param_m3.bin` を適用（B↔R スワップのみ）
4. `filmnoise` — フィルムグレイン付加
5. `watermark` — Leica ウォーターマーク合成

実際の B&W 変換は **`mialgo_monopan_cl.bin`（OpenCL シェーダー）** が `offcamb2y` の中で行い、
`leica_filter_param_m3.bin` の LUT はパイプライン内の BGR/RGB 順序補正にすぎない。
チャンネルミックス係数は `libmialgo_monopan.so` にハードコードされている。
