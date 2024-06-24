import base64
import random
import hashlib
import subprocess
import sys

try:
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'pycryptodome'])
finally:
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

def encrypt_message(message, key, iv):
    # note that the message is encoded
    
    # generates cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # encrypts data based on cipher
    encrypted_data = cipher.encrypt(pad(message, AES.block_size))
    
    # returns encrypted data (encoded utf-8)
    return encrypted_data

def decrypt_message(encrypted_message, key, iv):
    # note that encrypted_message is encoded
    
    # generates cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # decrypts data based on cipher
    decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    
    # returns decrypted data (encoded utf-8)
    return decrypted_data

def encrypt_to_str(message, key, iv):
    # encodes the encrypted data to utf-8
    encrypted_data = message.encode()
    
    # encrypts the message
    encrypted_data = encrypt_message(encrypted_data, key, iv)
    
    # decodes the encrypted data to string
    encrypted_data = base64.b64encode(encrypted_data).decode()
    return encrypted_data

def decrypt_from_str(encrypted_message, key, iv):
    
    # the encrypted message is converted to bytes
    # then it is decrypted using the decrypt_message function
    # subsequently, it is decoded from bytes to string (utf-8)
    decrypt_data = decrypt_message(base64.b64decode(encrypted_message.encode()), key, iv).decode('utf-8')
    return decrypt_data

def decrypt_array(array, key, iv):
    new_array = []
    for msg in array:
        new_msg = decrypt_from_str(msg, key, iv)
        new_array.append(new_msg)
    return new_array

def generateValues(password):
    # Generate a new hash
    SHA_key = hashlib.sha256(password.encode()).hexdigest()
    
    # sets IV
    iv = ""
    
    # Uses a seed to fixate the randomness
    random.seed(len(SHA_key))
    
    # Generate 32 random bytes based on the seed
    salt = random.randbytes(32)
    
    # Generate a key using Password-Based Key Derivation Function 2
    key = PBKDF2(SHA_key, salt, dkLen=32)
    
    # generates IV
    for _ in range(16):
        iv += SHA_key[random.randint(0, len(SHA_key) - 1)]
        
    # changes to bytes for AES
    iv = bytes(iv, 'utf-8')
    return iv, key