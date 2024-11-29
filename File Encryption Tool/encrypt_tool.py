import argparse
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# XOR Cipher (One-Time Pad)
def xor_cipher(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Caesar Cipher
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    return ''.join(chr((ord(char) + shift - 32) % 95 + 32) if 32 <= ord(char) <= 126 else char for char in text)

# AES Encryption/Decryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(data, key):
    iv, ciphertext = data[:AES.block_size], data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# RSA Encrypt/Decrypt
def rsa_encrypt(data, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

def rsa_decrypt(data, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(data)

# Key loading and generation
def load_key(file_path):
    with open(file_path, 'rb') as f:
        return f.read().strip()

def save_key(key, file_path):
    """Save key to the user-specified path."""
    key_dir = os.path.dirname(file_path) or "key_files"
    os.makedirs(key_dir, exist_ok=True)
    full_path = os.path.join(key_dir, os.path.basename(file_path))
    with open(full_path, 'wb') as f:
        f.write(key)
    return full_path

# Validation
def validate_encryption(data, encrypted_data, algorithm, key, args):
    if algorithm == "rsa":
        # Dynamically determine the private key path using args.key
        private_key_path = args.key.replace("rsa_public", "rsa_private") if "rsa_public" in args.key else "key_files/rsa_private.pem"
        
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file '{private_key_path}' not found for RSA validation.")
        
        # Load private key and decrypt
        private_key = RSA.import_key(open(private_key_path, 'rb').read())
        decrypted = rsa_decrypt(encrypted_data, private_key)
    elif algorithm == "caesar":
        decrypted = caesar_cipher(encrypted_data.decode('utf-8'), int(key), decrypt=True).encode('utf-8')
    elif algorithm == "otp":
        decrypted = xor_cipher(encrypted_data, key)
    elif algorithm == "aes":
        decrypted = aes_decrypt(encrypted_data, key)
    else:
        raise ValueError("Unsupported algorithm for validation")
    
    # Compare the decrypted data with the original
    if data == decrypted:
        print("Validation successful: The data matches the original.")
        return True
    else:
        print("Validation failed: The data does not match the original.")
        return False





# Command line argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description="File Encryption Tool with Validation")
    #this is for encryption 
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the file")
    #this is for decryption 
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the file")
    #this is which algorithm to use 
    parser.add_argument("--algorithm", choices=["caesar", "otp", "aes", "rsa"], required=True, help="Encryption algorithm")
    #this is which key to use
    parser.add_argument("--key", help="Path to key file")
    #this is the input file path 
    parser.add_argument("--input", required=True, help="Input file path")
    #this is the output file path
    parser.add_argument("--output", required=True, help="Output file path")
    #this is for validation 
    parser.add_argument("--validate", action="store_true", help="Validate encryption by decrypting and comparing")\
    #this is for aes key size
    parser.add_argument("--aes-keysize", type=int, choices=[128, 192, 256], help="Key size for AES (128, 192, or 256 bits). Defaults to 256 if not provided.")
    #this is for rsa key size
    parser.add_argument("--rsa-keysize", type=int, choices=[2048, 3072, 4096], help="Key size for RSA (2048, 3072, or 4096 bits). Defaults to 4096 if not provided.")
    return parser.parse_args()

# MAIN FUNCTION!
def main():
    args = parse_args()

    # Load input file
    if not os.path.exists(args.input):
        raise FileNotFoundError(f"Input file '{args.input}' not found.")
    with open(args.input, 'rb') as f:
        data = f.read()

    # Load or generate key
    key = None
    if args.encrypt:
        if args.key and os.path.exists(args.key):
            key = RSA.import_key(load_key(args.key)) if args.algorithm == "rsa" else load_key(args.key)
            print(f"Using existing key from: {args.key}")
        else:
            if args.algorithm == "aes":
                key_size = args.aes_keysize if args.aes_keysize else 256
                key = get_random_bytes(key_size // 8)
                key_path = save_key(key, args.key or "aes_key.key")
                print(f"AES key generated and saved to: {key_path}")
            elif args.algorithm == "rsa":
                key_size = args.rsa_keysize if args.rsa_keysize else 4096

                # Generate RSA keys
                rsa_key = RSA.generate(key_size)

                # Determine the key file names based on user input or defaults
                private_key_path = args.key.replace("rsa_public", "rsa_private") if args.key else "key_files/rsa_private.pem"
                public_key_path = args.key if args.key else "key_files/rsa_public.pem"

                # Save the keys
                private_key_path = save_key(rsa_key.export_key(), private_key_path)
                public_key_path = save_key(rsa_key.publickey().export_key(), public_key_path)

                print(f"RSA keys generated:\nPrivate Key: {private_key_path}\nPublic Key: {public_key_path}")
                key = rsa_key.publickey()
            elif args.algorithm == "otp":
                key = get_random_bytes(len(data))
                key_path = save_key(key, args.key or "otp_key.key")
                print(f"OTP key generated and saved to: {key_path}")
            elif args.algorithm == "caesar":
                import random
                shift_key = random.randint(1, 94)
                key_path = save_key(str(shift_key).encode('utf-8'), args.key or "caesar_key.key")
                print(f"Caesar Cipher key generated and saved to: {key_path}")
                key = str(shift_key).encode('utf-8')

            if isinstance(key, RSA.RsaKey):
                print(f"Key length: {key.size_in_bits() // 8} bytes ({key.size_in_bits()} bits)")
            else:
                print(f"Key length: {len(key)} bytes")
    elif args.decrypt:
        if not args.key:
            print("Key was not specified, try again. (Use --key to specify the key file)")
            return 0  # Exit the program with code 0

        key = load_key(args.key)

    # Encrypt or decrypt data
    result = None
    if args.encrypt:
        if args.algorithm == "caesar":
            shift = int(key)
            result = caesar_cipher(data.decode('utf-8'), shift).encode('utf-8')
            print(f"Caesar Encryption key: {shift}")
        elif args.algorithm == "otp":
            result = xor_cipher(data, key)
        elif args.algorithm == "aes":
            result = aes_encrypt(data, key)
        elif args.algorithm == "rsa":
            result = rsa_encrypt(data, key)
        
        # Validation block
        if args.validate:
            print("Validating encryption...")
            if not validate_encryption(data, result, args.algorithm, key, args):  # Pass args explicitly
                print("Validation failed: The decrypted data does not match the original.")
                return
    elif args.decrypt:
        if args.algorithm == "caesar":
            shift = int(key)
            result = caesar_cipher(data.decode('utf-8'), shift, decrypt=True).encode('utf-8')
            print("Caesar Decryption successful.")
        elif args.algorithm == "otp":
            result = xor_cipher(data, key)
            print("OTP Decryption successful.")
        elif args.algorithm == "aes":
            result = aes_decrypt(data, key)
            print("AES Decryption successful.")
        elif args.algorithm == "rsa":
            result = rsa_decrypt(data, RSA.import_key(key))
            print("RSA Decryption successful.")

    # Write to output file
    with open(args.output, 'wb') as f:
        f.write(result)



if __name__ == "__main__":
    main()
