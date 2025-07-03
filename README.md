# DES-CBC-Demo

This project provides an **educational implementation of the Data Encryption Standard (DES) in Cipher Block Chaining (CBC) mode** written in Python. It includes detailed debug prints that show each step of the DES encryption process, from initial permutations to key mixing and S-box substitutions.

## 🚀 Features
- DES initial and final permutations, expansion, S-box substitution, and permutation P implemented explicitly.
- CBC mode support with automatic padding.
- Generates a random 64-bit initialization vector (IV) for CBC mode.
- Step-by-step, human-readable logs for each round of DES.
- Outputs final ciphertext in hexadecimal format.

## 📂 How It Works
1. Converts plaintext to padded byte blocks of 8 bytes each.
2. XORs each plaintext block with the previous ciphertext block (or IV for the first block).
3. Encrypts each block with the DES Feistel structure over 16 rounds.
4. Concatenates all ciphertext blocks to form the final ciphertext.

## 📄 Example Usage
Run the script directly. The program:
- Encrypts the plaintext string `"hello world"` in CBC mode.
- Prints detailed logs for each block and DES round.
- Outputs the final ciphertext in hex.

```python
# Example entry point (already included at the end of the script)
iv_bytes = os.urandom(8)
iv = ''.join(f"{byte:08b}" for byte in iv_bytes)
plaintext = "hello world"
des_cbc_encrypt(plaintext, iv, round_keys)
