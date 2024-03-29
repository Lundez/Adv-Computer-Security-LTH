import socket
import AES
import os
import random
import time
import sys
import queue
import threading
from functools import wraps
from hmac_module import hmac_apply, hmac_compare, hmac_strip

KEY = "1231231234518743"

UDP_PORT = 5005
UDP_IP = "127.0.0.1"
UDP_IP_2 = "127.0.0.2"
UDP_DATA_BOB = (UDP_IP, UDP_PORT)
UDP_DATA_ALICE = (UDP_IP_2, UDP_PORT)

BUFF_SIZE = 1024
im_the_sender = False

input_queue = queue.Queue()


def gen_primes(n):
    """ Returns  a list of primes < n"""
    sieve = [True] * n
    for i in range(3, int(n**0.5) + 1, 2):
        if sieve[i]:
            sieve[i*i::2*i] = [False]*((n-i*i-1)//(2*i)+1)
    return [2] + [i for i in range(3, n, 2) if sieve[i]]


def diffie_calc(secret, base, prime):
    """
    :param secret, base, prime
    :return: the diffie-hellman calculation of the input
    """
    return (base**secret) % prime


def create_iv(s):
    """
    :param s: the secret received from diffie-hellman handshake
    :return: the initialization vector that can be created from this secret when made into binary and then padded/reduced
    """
    iv = '{0:08b}'.format(s)
    if len(iv) > 16:
        iv = iv[-16:]
    elif len(iv) < 16:
        size_left = 16 - len(iv)
        iv = '0'*size_left + iv
    print("12. Generated IV out of secret: %s" % iv)
    return iv


def receive(sock, udp_data):
    """
    This method is used by a thread that works in the background to receive messages. If you're the sender
    (i.e. "im_the_sender == True") it'll put the received content in a python Queue (asynchronous queue) else
    it'll believe it has been asked to handshake and follow from there.
    """
    while True:
        message = sock.recv(BUFF_SIZE)
        if message is not None:
            input_queue.put(message)

        if input_queue.qsize() >= 3 and not im_the_sender:
            print("16. Receiving message: inbox >= 3 (prime, base & A)")
            prime = from_byte(input_queue.get())        # int(input_queue.get().decode())
            base = from_byte(input_queue.get())         # int(input_queue.get().decode())
            A = from_byte(input_queue.get())            # int(input_queue.get().decode())

            # Check that all are not None? Or try? Returns empty-exception if empty

            secret = random.randint(0, 10000)
            print("17. Calculate secret (randint(0,10000): %s" % secret)
            B = diffie_calc(secret, base, prime)
            print("18. Calculate B with DH and then send: %s" % B)
            sock.sendto(to_byte(B), udp_data)  # Need to exchange the base/prime too

            s = diffie_calc(secret, A, prime)  # s == IV if padded
            print("19. Calculate supersecret: %s" % s)
            iv = create_iv(s)

            while True:
                message = sock.recv(BUFF_SIZE)
                print("20. Received message: %s" % message)
                if message is not None:
                    print("21. Check if HMAC is correct")
                    if not hmac_compare(message, iv.encode()):
                        print("Something went wrong with the message, HMAC doesnt work")
                        break
                    print("22. HMAC correct. Now strip HMAC: %s (result)" % hmac_strip(message))
                    msg = AES.cbc_decrypt(hmac_strip(message), KEY, iv)

                    print("Received: %s" % msg)
                    break


def to_byte(number):
    return str(number).encode()


def from_byte(number):
    return int(number.decode())


def cache_gcd(f):
    cache = {}

    @wraps(f)
    def wrapped(a, b):
        key = (a, b)
        try:
            result = cache[key]
        except KeyError:
            result = cache[key] = f(a, b)
        return result
    return wrapped


@cache_gcd
def gcd(a,b):
    while b != 0:
        a, b = b, a % b
    return a


def prim_roots(modulo):
    required_set = {num for num in range(1, modulo) if gcd(num, modulo)}
    return [g for g in range(1, modulo) if required_set == {pow(g, powers, modulo)
            for powers in range(1, modulo)}]


def init_handshake(sock, udp_data):
    secret = random.randint(0, 10000)
    print("5. Generate secret (randint(0,10000)): %s" % secret)
    prime = random.choice(primes)
    print("6. Draw random prime from list of primes: %s" % prime)
    roots = prim_roots(prime)
    base = random.choice(roots)
    print("7. Generate random base (out of primitive roots of prime): %s" % base)
    A = diffie_calc(secret, base, prime)
    print("8. Calculate our A with diffie-hellman: %s" % A)
    print("9. Send all data to receiver")
    sock.sendto(to_byte(prime), udp_data)
    sock.sendto(to_byte(base), udp_data)
    sock.sendto(to_byte(A), udp_data)
    print("10. Wait for return (B) to calculate our diffie-hellman super-secret")
    while True:
        if not input_queue.empty():
            break
        time.sleep(.5)

    B = from_byte(input_queue.get(0))

    s = diffie_calc(secret, B, prime)
    print("11. Calculate super-secret with DH and return IV out of this: %s" % s)
    return create_iv(s)


def send_message(message, sock, udp_data):
    global im_the_sender
    im_the_sender = True
    print("4. Sending message (%s), init_handshake (DH)" % message)
    iv = init_handshake(sock, udp_data)  # == IV
    message = AES.cbc_encrypt(message, KEY, iv)
    print("13. Encrypted message (Key, IV, message used): %s" % message)
    message = hmac_apply(message, iv.encode())
    print("14. Applied HMAC to encrypted msg+IV: %s" % message)
    print("15. Now sending encrypted message")
    sock.sendto(message, udp_data)
    im_the_sender = False


# Skapa en print av allt som händer
# Skicka fil?

if __name__ == '__main__':
    user = sys.argv[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP
    primes = gen_primes(1000)                               # Proof of concept
    print("1. Generate prime list with all primes below 1000, amount: %s" % len(primes))

    if user.lower() == "bob":
        UDP_DATA = UDP_DATA_BOB
        UDP_SEND = UDP_DATA_ALICE
    else:
        UDP_DATA = UDP_DATA_ALICE
        UDP_SEND = UDP_DATA_BOB

    sock.bind(UDP_DATA)

    thread = threading.Thread(target=receive, args=(sock, UDP_SEND))
    thread.start()
    print("2. Starting background thread that'll receive data")
    print("3. Start while-loop for input to send message\n")

    print("Write a message to send:")
    while True:
        message_input = input()
        send_message(message_input, sock, UDP_SEND)
        print("Sent: %s" % message_input)