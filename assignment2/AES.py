from Crypto.Cipher import AES
import base64
import binascii, os

# os.urandom: Return a string of size random bytes suitable for cryptographic use.

INTERRUPT = u'\u0001'
BLOCK_SIZE = 16
PAD = u'\u0000'

def cbc_encrypt(message, key, iv):
    """ Encrypts a message in AES CBC mode with a given key & IV
    ACCEPTS: Three strings, the plaintext message, the key and the initializing vector
    RETURNS: A bytes string of base64 encoded ciphertext
    """
    message = add_padding(message)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(aes.encrypt(message))      # remove decode


def cbc_decrypt(encrypted, key, iv):
    """ Decrypts a ciphertext in AES CBC mode with a given key & IV
    ACCEPTS: Two strings, the base64 encoded ciphertext, the key and the initializing vector
    RETURNS: A bytes string of the plaintext message
    """
    aes = AES.new(key, AES.MODE_CBC, iv)
    return strip_padding(aes.decrypt(base64.b64decode(encrypted)).decode())


def add_padding(data):
    """
    :param data:
    :return: padded data as
    """
    new_data = ''.join([data, INTERRUPT])
    new_data_len = len(new_data)
    remaining_len = BLOCK_SIZE - new_data_len
    to_pad_len = remaining_len % BLOCK_SIZE
    pad_string = PAD * to_pad_len
    return ''.join([new_data, pad_string])


def strip_padding(data):
    return data.rstrip(PAD).rstrip(INTERRUPT)   # [x for x in data if x != PAD and x != INTERRUPT]


if __name__ == "__main__":
    Key = "0000000000000000"
    plain_text = "110 1 1"
    iv = os.urandom(16)

    cipher_text = cbc_encrypt(plain_text, Key, iv)
    decrypted_text = cbc_decrypt(cipher_text, Key, iv)

    print("Original message:\t%s" % plain_text)
    print("Encrypted message:\t%s" % cipher_text)
    print("Decrypted message:\t%s" % decrypted_text)