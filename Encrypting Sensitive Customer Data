from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt_customer_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def decrypt_customer_data(encrypted_data, key):
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:AES.block_size]
    ciphertext = encrypted_data_bytes[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Example usage
key = get_random_bytes(16)  # AES-128 key
customer_data = "Account Number: 123456789"

# Encrypting customer data
encrypted_data = encrypt_customer_data(customer_data, key)
print(f"Encrypted Customer Data: {encrypted_data}")

# Decrypting customer data
decrypted_data = decrypt_customer_data(encrypted_data, key)
print(f"Decrypted Customer Data: {decrypted_data}")
