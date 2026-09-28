def encrypt(key, iv, plaintext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
