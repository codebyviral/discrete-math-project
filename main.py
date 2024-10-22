from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ct_bytes

def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

key = get_random_bytes(16)  # Random 16-byte key (AES-128)
plaintext = "Hello, World!"

iv, ciphertext = aes_encrypt(plaintext, key)
print(f"IV: {iv.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")

decrypted_text = aes_decrypt(iv, ciphertext, key)
print(f"Decrypted Text: {decrypted_text}")