import os
import struct
import numpy as np

SOURCE_DIR = "decrypted_luts"
DEST_DIR = "converted_bins"

if not os.path.exists(DEST_DIR):
    os.makedirs(DEST_DIR)

def read_cube_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    size = None
    data = []
    
    # Simple parser assuming standard CUBE format
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("TITLE") or line.startswith("DOMAIN"):
            continue
        
        if line.startswith("LUT_3D_SIZE"):
            size = int(line.split()[1])
            continue
            
        parts = line.split()
        if len(parts) == 3:
            try:
                r, g, b = float(parts[0]), float(parts[1]), float(parts[2])
                data.append((r, g, b))
            except ValueError:
                continue

    if size is None:
        # Infer size if not specified (cube root of data count)
        size = int(round(len(data) ** (1/3.0)))
        
    return size, data

def convert_to_bin(filename, size, data, order='RGB'):
    # Standard .bin usually expects RGB float32 data
    # Some tools might expect specific ordering.
    # CUBE standard is: R varies fastest, then G, then B. (Loop B, then G, then R)
    # i.e. data[0] is (0,0,0), data[1] is (1/N, 0, 0) ...
    
    # Convert to numpy array for easier manipulation if needed, 
    # but list of tuples is fine for simple writing.
    
    # Verify data count
    if len(data) != size * size * size:
        print(f"Warning: Data count {len(data)} does not match size {size}^3 ({size**3}) for {filename}")
        
    dest_path = os.path.join(DEST_DIR, filename.replace(".cube", ".bin"))
    
    with open(dest_path, 'wb') as f:
        for r, g, b in data:
            # Clamp values to 0.0 - 1.0 (just in case)
            # r = max(0.0, min(1.0, r))
            # g = max(0.0, min(1.0, g))
            # b = max(0.0, min(1.0, b))
            
            if order == 'RGB':
                f.write(struct.pack('fff', r, g, b))
            elif order == 'BGR':
                f.write(struct.pack('fff', b, g, r))
                
    print(f"  Converted {filename} -> {os.path.basename(dest_path)} (Size: {size})")

print("Converting .cube to .bin...")

for filename in os.listdir(SOURCE_DIR):
    if not filename.endswith(".cube"):
        continue
        
    filepath = os.path.join(SOURCE_DIR, filename)
    try:
        size, data = read_cube_file(filepath)
        convert_to_bin(filename, size, data)
    except Exception as e:
        print(f"  Error converting {filename}: {e}")

print("Done.")
