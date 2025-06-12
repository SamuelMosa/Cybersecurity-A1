import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_file(filepath, privkey_path, output_path):
    with open(filepath, 'rb') as f:
        data = f.read()

    with open(privkey_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    rsa_key_len = private_key.size_in_bytes()

    enc_aes_key = data[:rsa_key_len]
    nonce = data[rsa_key_len:rsa_key_len+16]
    tag = data[rsa_key_len+16:rsa_key_len+32]
    ciphertext = data[rsa_key_len+32:]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Datei entschlüsselt und gespeichert als: {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WhistleDrop Datei entschlüsseln")
    parser.add_argument("encrypted_file", help="Pfad zur verschlüsselten .bin Datei")
    parser.add_argument("private_key", help="Pfad zum privaten RSA-Schlüssel (.pem)")
    parser.add_argument("--output", default="decrypted_output.pdf", help="Pfad für entschlüsselte Datei")

    args = parser.parse_args()

    if not os.path.exists(args.encrypted_file):
        print("Verschlüsselte Datei nicht gefunden!")
        exit(1)
    if not os.path.exists(args.private_key):
        print("Privater Schlüssel nicht gefunden!")
        exit(1)

    decrypt_file(args.encrypted_file, args.private_key, args.output)
