from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib

# Function to encrypt data using AES
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ct_bytes

# Function to decrypt data using AES
def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Function to generate HMAC for integrity verification
def generate_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

# Example usage
key = get_random_bytes(16)  # Generate a random 16-byte key (AES-128)
hmac_key = get_random_bytes(16)  # Generate a random key for HMAC
plaintext = "Sensitive Transaction Data"

# Encrypt the plaintext
iv, ciphertext = aes_encrypt(plaintext, key)
print(f"IV: {iv.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")

# Generate HMAC for the ciphertext
hmac_value = generate_hmac(ciphertext, hmac_key)
print(f"HMAC: {hmac_value}")

# Decrypt the ciphertext
decrypted_text = aes_decrypt(iv, ciphertext, key)
print(f"Decrypted Text: {decrypted_text}")

# Verify HMAC (for demonstration purposes)
if hmac.compare_digest(hmac_value, generate_hmac(ciphertext, hmac_key)):
    print("HMAC verification successful. Data integrity is intact.")
else:
    print("HMAC verification failed. Data may have been altered.")