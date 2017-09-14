import socket
import AES
import os
import random
import time
import sys
import queue
import threading
from hmac_module import hmac_apply, hmac_compare, hmac_strip

KEY = "1231231234518743"

UDP_PORT = 5005
UDP_IP = "127.0.0.1"
UDP_IP_2 = "127.0.0.2"
UDP_DATA_BOB = (UDP_IP, UDP_PORT)
UDP_DATA_ALICE = (UDP_IP_2, UDP_PORT)

BUFF_SIZE = 1024
#prime = 23
#base = 5 prime & base removed
im_the_sender = False

input_queue = queue.Queue()

# Darnit! We must change the diffie hellman! base&prime to be announced publicly!
# Khan Academy has a good video on how it works!!


def gen_primes(n):
    """ Returns  a list of primes < n """
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

    return iv


def receive(sock, udp_data):
    """
    This method is used by a thread that works in the background to receive messages. If you're the sender
    (i.e. "im_the_sender == True") it'll put the received content in a python Queue (asynchronous queue) else
    it'll believe it has been asked to handshake and follow from there.
    """
    while True:
        # if A != None --> input queue.
        # if size >= 3 && not im_the_sender --> initiate handshake other way around
        message = sock.recv(BUFF_SIZE)
        if message is not None:
            input_queue.put(message)
        if input_queue.qsize() >= 3 and not im_the_sender:
            prime = from_byte(input_queue.get())        # int(input_queue.get().decode())
            base = from_byte(input_queue.get())         # int(input_queue.get().decode())
            A = from_byte(input_queue.get())            # int(input_queue.get().decode())
            # Check that all are not None? Or try? Returns empty-exception if empty
            secret = random.randint(0, 10000)
            B = diffie_calc(secret, base, prime)
            sock.sendto(to_byte(B), udp_data)  # Need to exchange the base/prime too
            s = diffie_calc(secret, A, prime)  # s == IV if padded
            iv = create_iv(s)
            while True:
                message = sock.recv(BUFF_SIZE)
                if message is not None:
                    if not hmac_compare(message, iv.encode()):
                        print("Something went wrong with the message, HMAC doesnt work")
                        break

                    msg = AES.cbc_decrypt(hmac_strip(message), KEY, iv)
                    print("Received: %s" % msg)
                    break

        """
        A = sock.recv(BUFF_SIZE)
        if A is not None and im_the_sender:
            input_queue.put(A)
        elif A is not None:
            secret = random.randint(0, 10000)
            print(len(A))
            B = diffie_calc(secret, base, prime)
            sock.sendto(str(B).encode(), udp_data)             # Need to exchange the base/prime too
            s = diffie_calc(secret, int(A.decode()), prime)    # s == IV if padded
            iv = create_iv(s)
            while True:
                message = sock.recv(BUFF_SIZE)
                if message is not None:
                    if not hmac_compare(message, iv.encode()):
                        print("Something went wrong with the message, HMAC doesnt work")
                        break

                    msg = AES.cbc_decrypt(hmac_strip(message), KEY, iv)
                    print("Received: %s" % msg)
                    break
        """


def to_byte(number):
    return str(number).encode()


def from_byte(number):
    return int(number.decode())


def init_handshake(sock, udp_data):
    secret = random.randint(0, 10000)
    prime = random.choice(primes)       # added
    base = random.randint(0, 10000)     # added
    A = diffie_calc(secret, base, prime)

    sock.sendto(to_byte(prime), udp_data)
    sock.sendto(to_byte(base), udp_data)
    sock.sendto(to_byte(A), udp_data)
    #sock.sendto(str(prime).encode(), udp_data)      # Extract to be a "to binary" and then "from binary"
    #sock.sendto(str(base).encode(), udp_data)
    #sock.sendto(str(A).encode(), udp_data)

    while True:
        if not input_queue.empty():
            break
        time.sleep(.5)

    B = from_byte(input_queue.get(0))
    s = diffie_calc(secret, B, prime)
    return create_iv(s)


def send_message(message, sock, udp_data):
    global im_the_sender
    im_the_sender = True
    iv = init_handshake(sock, udp_data)  # == IV
    message = AES.cbc_encrypt(message, KEY, iv)
    message = hmac_apply(message, iv.encode())
    sock.sendto(message, udp_data)
    im_the_sender = False

if __name__ == '__main__':
    user = sys.argv[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP
    primes = gen_primes(1000)

    if user.lower() == "bob":
        UDP_DATA = UDP_DATA_BOB
        UDP_SEND = UDP_DATA_ALICE
    else:
        UDP_DATA = UDP_DATA_ALICE
        UDP_SEND = UDP_DATA_BOB

    sock.bind(UDP_DATA)

    thread = threading.Thread(target=receive, args=(sock, UDP_SEND))
    thread.start()
    print("Write a message to send:")
    while True:
        message_input = input()
        send_message(message_input, sock, UDP_SEND)
        print("Sent: %s" % message_input)


"""
    message = "Hey bob, how are you!?"
    iv = os.urandom(16)
    print(iv)

    cipher_text = AES.cbc_encrypt(message, KEY, iv)
    #sock.bind(UDP_DATA)
    sock.sendto(iv, UDP_DATA)
    time.sleep(1)
    sock.sendto(cipher_text.encode(), UDP_DATA)
"""