import os
import base64
from Crypto.Cipher import AES

# Key from Frida
KEY_HEX = "6247567059324666593246745a584a685832567559334a356348526661325635"
KEY = bytes.fromhex(KEY_HEX)

SOURCE_DIR = "extracted_files/luts"
DEST_DIR = "decrypted_luts"

if not os.path.exists(DEST_DIR):
    os.makedirs(DEST_DIR)

print(f"Decrypting LUTs from {SOURCE_DIR} to {DEST_DIR}...")

count = 0
for filename in os.listdir(SOURCE_DIR):
    if not filename.endswith(".CUBE.enc"):
        continue
        
    filepath = os.path.join(SOURCE_DIR, filename)
    dest_path = os.path.join(DEST_DIR, filename.replace(".CUBE.enc", ".cube"))
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            
        # 1. Base64 Decode (concatenated parts)
        parts = content.split(b']')
        decoded_parts = []
        for part in parts:
            if len(part) == 0: continue
            try:
                decoded = base64.b64decode(part)
                decoded_parts.append(decoded)
            except:
                pass
        
        full_binary = b"".join(decoded_parts)
        
        if len(full_binary) < 32:
            print(f"Skipping {filename}: Too small")
            continue
            
        # 2. Extract IV (first 16 bytes) and Tag (last 16 bytes)
        iv = full_binary[:16]
        tag = full_binary[-16:]
        ciphertext = full_binary[16:-16]
        
        # 3. Decrypt AES-256-GCM
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        
        with open(dest_path, 'wb') as f:
            f.write(decrypted)
            
        print(f"  [OK] {filename} -> {os.path.basename(dest_path)}")
        count += 1
        
    except Exception as e:
        print(f"  [FAIL] {filename}: {e}")

print(f"\nFinished. Decrypted {count} files.")
