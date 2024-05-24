import hashlib

def SHA_256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

def SHA_256_adv(hash_string):
    sha_adv = SHA_256(hash_string)
    value = 0
    for i in range(len(sha_adv)):
        value += ord(sha_adv[i]) ^ ord(hash_string[i % len(hash_string)])
    return value

string = "12345"
encrypt = SHA_256(string)
encrypt_adv = SHA_256_adv(string)

print(encrypt)
print(encrypt_adv)