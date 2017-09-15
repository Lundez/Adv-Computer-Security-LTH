import hashlib
import hmac

# ENCRYPT then MAC
# Use IV as part of calculation
# MSG+MAC
# LEN(MAC)
# MSG+MAC - MAC
# = MSG
# HMAC(MSG)
# IF ^ == MAC --> WIN

KEY = bytearray("0123456789".encode())


def hmac_apply(cipher_text, iv):
    hmac_obj = hmac.new(KEY)
    hmac_obj.update(cipher_text + iv)
    mac = hmac_obj.digest()
    return cipher_text + mac


def hmac_compare(ciphertext, iv):
    hmac_obj = hmac.new(KEY)
    hmac_obj.update(ciphertext[:-16] + iv)
    mac = hmac_obj.digest()
    return hmac.compare_digest(mac, ciphertext[-16:])


def hmac_strip(ciphertext):
    return ciphertext[:-16]


if __name__ == '__main__':
    mac = hmac_apply("lawl".encode(), "101".encode())
    print(hmac_compare(mac, "101".encode()))