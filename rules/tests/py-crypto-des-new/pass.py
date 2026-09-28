def encrypt(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.encrypt(plaintext)
