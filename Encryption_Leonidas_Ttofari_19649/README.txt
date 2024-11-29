										-----File Encryption Tool-----

# Description
 This tool provides encryption and decryption functionalities for files using various algorithms such as:
 - Caesar Cipher
 - XOR Cipher (One Time Pad)
 - AES (Advanced Encryption Standard) 
 - RSA (Rivest Shamir Adleman)

# Requirements
 - Python 3.8+ (check with 'python --version', install from https://www.python.org/)
 - pycryptodome library (install with `pip install pycryptodome`)


										  ---How to use format---

# Encrypt a file inside bash
 python encrypt_tool.py --encrypt --algorithm <algorithm> --key <key_file> --input <input_file> --output <output_file> 

# Decrypt a file inside bash
 python encrypt_tool.py --decrypt --algorithm <algorithm> --key <key_file> --input <input_file> --output <output_file>

# Arguments
 --algorithm: Choose from `caesar`, `otp`, `aes`, `rsa`.
 --key: Path to the key file.
 --input: Path to the input file.
 --output: Path to the output file.
 --validate: To validate encryption by decrypting and comparing with the original file.		 	(optional)
 --aes-keysize: Choose the key size for AES (128|192|256 bits), NOTE:it defaults to 256 bits.		(optional)
 --rsa-keysize: Choose the key size for RSA (2048|3072|4096 bits), NOTE:it defaults to 4096 bits.	(optional)


										      ---Examples---

# Caesar Encryption inside bash
 python encrypt_tool.py --encrypt --algorithm caesar --key key_files/caesar_key.key --input test_files/sample_input.txt --output output_files/caesar_encrypted.bin --validate

# Caesar Decryption inside bash
 python encrypt_tool.py --decrypt --algorithm caesar --key key_files/caesar_key.key --input output_files/caesar_encrypted.bin --output output_files/caesar_decrypted.txt
=========================================================================================================================================================================================
# One-Time-Pad Encryption inside bash
 python encrypt_tool.py --encrypt --algorithm otp --key key_files/otp_key.key --input test_files/sample_input.txt --output output_files/otp_encrypted.bin --validate

# One-Time-Pad Decryption inside bash
 python encrypt_tool.py --decrypt --algorithm otp --key key_files/otp_key.key --input output_files/otp_encrypted.bin --output output_files/otp_decrypted.txt
=========================================================================================================================================================================================
# AES Encryption inside bash
 python encrypt_tool.py --encrypt --algorithm aes --aes-keysize 128 --key key_files/aes_key.key --input test_files/sample_input.txt --output output_files/aes_encrypted.bin --validate 
 python encrypt_tool.py --encrypt --algorithm aes --aes-keysize 192 --key key_files/aes_key_image.key --input test_files/sample_image.png --output output_files/aes_encrypted_image.bin --validate 
# AES Decryption inside bash
 python encrypt_tool.py --decrypt --algorithm aes --key key_files/aes_key.key --input output_files/aes_encrypted.bin --output output_files/aes_decrypted.txt
 python encrypt_tool.py --decrypt --algorithm aes --key key_files/aes_key_image.key --input output_files/aes_encrypted_image.bin --output output_files/aes_decrypted_image.png

=========================================================================================================================================================================================
# RSA Encryption inside bash
 python encrypt_tool.py --encrypt --algorithm rsa --rsa-keysize 2048 --key key_files/rsa_public.pem --input test_files/sample_input.txt --output output_files/rsa_encrypted.bin --validate 
 python encrypt_tool.py --encrypt --algorithm rsa --rsa-keysize 4096 --key key_files/rsa_public_image.pem --input test_files/sample_image.png --output output_files/rsa_encrypted_image.bin --validate 
 
# RSA decryption inside bash
 python encrypt_tool.py --decrypt --algorithm rsa --key key_files/rsa_private.pem --input output_files/rsa_encrypted.bin --output output_files/rsa_decrypted.txt
 python encrypt_tool.py --decrypt --algorithm rsa --key key_files/rsa_private_image.pem --input output_files/rsa_encrypted_image.bin --output output_files/rsa_decrypted_image.png


										   ---Files Included---
 1. `encrypt_tool.py`: The encryption tool script.
 2. Sample key files for different algorithms.
 3. Test input and output files for encryption and decryption.

																			 	Developed by - LeonidPower.