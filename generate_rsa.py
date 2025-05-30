import os
import json
from Crypto.PublicKey import RSA

NUM_KEYS = 10
KEY_SIZE = 2048
PRIVATE_KEY_DIR = "journalist_keys"
PUBLIC_KEY_FILE = "public_keys.json"

os.makedirs(PRIVATE_KEY_DIR, exist_ok=True)

public_keys = {}

for i in range(NUM_KEYS):
    key = RSA.generate(KEY_SIZE)

    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()

    key_id = f"key_{i:03d}"
    public_keys[key_id] = public_key_pem.decode('utf-8')

    with open(os.path.join(PRIVATE_KEY_DIR, f"{key_id}_private.pem"), "wb") as f:
        f.write(private_key_pem)

# Save public keys to JSON for server use
with open(PUBLIC_KEY_FILE, "w") as f:
    json.dump(public_keys, f, indent=2)

print(f" {NUM_KEYS} RSA-Schlüsselpaare erzeugt.")
print(f" Private Keys im Ordner: {PRIVATE_KEY_DIR}")
print(f" Public Keys gespeichert in: {PUBLIC_KEY_FILE}")
