# Ziad hamdy mohamed, ID: 13004722
# Abdelhamid taher el-naggar ID: 13006203
# Adham bahaa, ID: 13004340
import os

# DES Tables (from starter notebook)
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

round_keys = ["010101010101010101010101010101010101010101010101" for _ in range(16)]

def permute(bits, table):
    return ''.join([bits[p-1] for p in table])

def xor_bits(a, b):
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

def apply_sboxes(bits):
    output = []
    for i in range(8):
        chunk = bits[i*6 : (i+1)*6]
        row = int(chunk[0] + chunk[5], 2)
        col = int(chunk[1:5], 2)
        val = S_BOXES[i][row][col]
        output.append(f"{val:04b}")
    return ''.join(output)

def bytes_to_bits(data):
    return ''.join(f"{byte:08b}" for byte in data)

def bits_to_bytes(bits):
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def pad_data(data):
    pad_len = 8 - (len(data) % 8)
    if pad_len == 0:
        pad_len = 8
    return data + bytes([pad_len] * pad_len)

def format_bits(bits, group_size):
    return ' '.join([bits[i:i+group_size] for i in range(0, len(bits), group_size)])

def des_encrypt_block(block, round_keys):
    print("Starting DES encryption for block:")
    print(f"Block (binary): {format_bits(block, 8)}")
    permuted = permute(block, IP)
    print(f"After Initial Permutation: {format_bits(permuted, 8)}")
    left, right = permuted[:32], permuted[32:]
    print(f"Split into L0: {format_bits(left, 4)}")
    print(f"            R0: {format_bits(right, 4)}")
    for round_num in range(16):
        print(f"\nRound {round_num + 1}:")
        expanded = permute(right, E)
        print(f"Expansion (E): {format_bits(expanded, 6)}")
        mixed = xor_bits(expanded, round_keys[round_num])
        print(f"After Key mixing: {format_bits(mixed, 6)}")
        substituted = apply_sboxes(mixed)
        print(f"After S-boxes: {format_bits(substituted, 4)}")
        permuted_p = permute(substituted, P)
        print(f"After Permutation P: {format_bits(permuted_p, 4)}")
        new_right = xor_bits(left, permuted_p)
        print(f"New R{round_num + 1}: {format_bits(new_right, 4)}")
        left, right = right, new_right
        print(f"L{round_num + 1}: {format_bits(left, 4)}")
    combined = right + left
    ciphertext = permute(combined, FP)
    print(f"\nAfter swapping and Final Permutation: {format_bits(ciphertext, 8)}")
    return ciphertext

def des_cbc_encrypt(plaintext, iv, round_keys):
    print("CBC Mode Encryption")
    print(f"Plaintext: {plaintext}")
    plaintext_bytes = plaintext.encode('utf-8')
    padded_bytes = pad_data(plaintext_bytes)
    print(f"Padded plaintext (hex): {padded_bytes.hex()}")
    blocks = [padded_bytes[i:i+8] for i in range(0, len(padded_bytes), 8)]
    ciphertext_blocks = []
    previous = iv
    for i, block in enumerate(blocks):
        print(f"\nEncrypting Block {i + 1}:")
        block_bits = bytes_to_bits(block)
        print(f"Block (binary): {format_bits(block_bits, 8)}")
        print(f"XOR with IV/Previous Ciphertext: {format_bits(previous, 8)}")
        xor_block = xor_bits(block_bits, previous)
        print(f"Result after XOR: {format_bits(xor_block, 8)}")
        encrypted_bits = des_encrypt_block(xor_block, round_keys)
        ciphertext_blocks.append(encrypted_bits)
        previous = encrypted_bits
        print(f"Ciphertext Block {i + 1}: {format_bits(encrypted_bits, 8)}")
    ciphertext = b''.join(bits_to_bytes(bits) for bits in ciphertext_blocks)
    print(f"\nFinal Ciphertext (hex): {ciphertext.hex().upper()}")
    return ciphertext


# Example usage:
iv_bytes = os.urandom(8)
iv = ''.join(f"{byte:08b}" for byte in iv_bytes)
plaintext = "hello world"
des_cbc_encrypt(plaintext, iv, round_keys)