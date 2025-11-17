#!/usr/bin/env python3
"""
hybrid_crypto.py
Simple hybrid encryption CLI using AES-GCM + RSA-OAEP.

Usage examples:
  # Generate RSA keypair
  python hybrid_crypto.py genkeys --private private.pem --public public.pem --keysize 2048

  # Encrypt file.txt
  python hybrid_crypto.py encrypt --in file.txt --out file_encrypted.bin --keyout key_encrypted.bin --pub public.pem

  # Decrypt
  python hybrid_crypto.py decrypt --in file_encrypted.bin --keyin key_encrypted.bin --priv private.pem --out file_decrypted.txt
"""
import argparse
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ---- Key generation ----
def generate_rsa_keypair(private_path: str, public_path: str, key_size: int = 2048, passphrase: bytes | None = None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    # Private key serialization (PEM). Optionally encrypted with passphrase.
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    with open(private_path, "wb") as f:
        f.write(priv_pem)
    # Public key (PEM)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pub_pem)
    print(f"RSA keypair generated: {private_path}, {public_path}")

# ---- Encryption ----
def encrypt_file(input_path: str, output_file_encrypted: str, output_key_encrypted: str, public_key_path: str):
    # 1. create random AES key (32 bytes => AES-256)
    aes_key = AESGCM.generate_key(bit_length=256)  # returns bytes
    aesgcm = AESGCM(aes_key)
    # 2. read plaintext file (binary so works for any file)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    # 3. encrypt with AES-GCM, generate nonce (12 bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)  # ciphertext includes tag (auth)
    # write file_encrypted.bin: nonce + ciphertext
    with open(output_file_encrypted, "wb") as f:
        f.write(nonce + ciphertext)
    # 4. encrypt AES key with RSA public key using OAEP
    with open(public_key_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read(), backend=default_backend())
    encrypted_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_key_encrypted, "wb") as f:
        f.write(encrypted_key)
    print(f"Encrypted file saved to {output_file_encrypted}")
    print(f"Encrypted AES key saved to {output_key_encrypted}")

# ---- Decryption ----
def decrypt_file(encrypted_file_path: str, encrypted_key_path: str, private_key_path: str, output_plain_path: str, passphrase: bytes | None = None):
    # load private key (optionally encrypted)
    with open(private_key_path, "rb") as f:
        priv_bytes = f.read()
    private_key = serialization.load_pem_private_key(priv_bytes, password=passphrase, backend=default_backend())
    # load encrypted AES key
    with open(encrypted_key_path, "rb") as f:
        encrypted_key = f.read()
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # read encrypted file, split nonce (first 12 bytes) and ciphertext
    with open(encrypted_file_path, "rb") as f:
        data = f.read()
    if len(data) < 13:
        raise ValueError("Encrypted file too short or corrupted.")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    with open(output_plain_path, "wb") as f:
        f.write(plaintext)
    print(f"Decryption complete. Plaintext written to {output_plain_path}")

# ---- CLI ----
def main():
    parser = argparse.ArgumentParser(description="Hybrid AES-GCM + RSA-OAEP file encryptor/decryptor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkeys", help="Generate RSA keypair")
    p_gen.add_argument("--private", required=True, help="Output private key PEM path")
    p_gen.add_argument("--public", required=True, help="Output public key PEM path")
    p_gen.add_argument("--keysize", type=int, default=2048, help="RSA key size (bits)")
    p_gen.add_argument("--passphrase", help="Optional passphrase to encrypt private key (string)")

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--in", dest="infile", required=True, help="Input file to encrypt")
    p_enc.add_argument("--out", dest="outfile", required=True, help="Output encrypted file (file_encrypted.bin)")
    p_enc.add_argument("--keyout", required=True, help="Output RSA-encrypted AES key (key_encrypted.bin)")
    p_enc.add_argument("--pub", required=True, help="Public key PEM file")

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--in", dest="infile", required=True, help="Input encrypted file (file_encrypted.bin)")
    p_dec.add_argument("--keyin", required=True, help="Input RSA-encrypted AES key (key_encrypted.bin)")
    p_dec.add_argument("--priv", required=True, help="Private key PEM file")
    p_dec.add_argument("--out", dest="outfile", required=True, help="Output decrypted file")
    p_dec.add_argument("--passphrase", help="Passphrase for private key if it is encrypted")

    args = parser.parse_args()

    if args.cmd == "genkeys":
        passphrase = args.passphrase.encode() if args.passphrase else None
        generate_rsa_keypair(args.private, args.public, key_size=args.keysize, passphrase=passphrase)
    elif args.cmd == "encrypt":
        encrypt_file(args.infile, args.outfile, args.keyout, args.pub)
    elif args.cmd == "decrypt":
        passphrase = args.passphrase.encode() if args.passphrase else None
        decrypt_file(args.infile, args.keyin, args.priv, args.outfile, passphrase=passphrase)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
