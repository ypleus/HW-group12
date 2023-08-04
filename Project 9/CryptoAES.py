import threading
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(
        pad(plaintext.to_bytes(16, 'big'), AES.block_size))
    return ciphertext.hex()


if __name__ == "__main__":
    key = bytes.fromhex('00000000000000000000000000000001')
    num_threads = 16
    num_strings = 10000

    hex_strings = [
        random.randint(0x0, 0xFFFFFFFFFFFFFFFF) for _ in range(num_strings)
    ]

    start_time = time.time()
    threads = []
    for i in range(0, num_strings, num_strings // num_threads):
        thread_strings = hex_strings[i:i + num_strings // num_threads]
        thread = threading.Thread(
            target=lambda strings: [encrypt(s, key) for s in strings],
            args=(thread_strings, ))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    print("Time: ", end_time - start_time)
