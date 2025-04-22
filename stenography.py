from PIL import Image
from bitarray import bitarray
from bitarray.util import ba2int, int2ba
from pathlib import Path
import io
import secrets
import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAX_SEED_BITS = 16
MAX_SIZE_BITS = 17

def encrypt(password: bytes, plaintext: bytes):
    # 1. derive aes key from password with random salt
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=1_000_000)
    key = kdf.derive(password)

    # 2. create IV for aes (128 bits)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # 3. return salt, iv, ciphertext
    return salt, iv, ciphertext 

def decrypt(password: bytes, salt: bytes, ciphertext: bytes, iv: bytes):
    # 1. derive aes key from password and salt 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=1_000_000)
    key = kdf.derive(password)

    # 2. decrypt with aes
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(bytes(ciphertext)) + decryptor.finalize()

    return plaintext




def enscribe(file, secret):
    def binary(x):
        return format(x, '08b')
    secret = secret.encode('utf8')

    secret_ba = bitarray(''.join([binary(c) for c in secret]))

    # used to seed RNG for bit placement
    seed_ba = bitarray(MAX_SEED_BITS)
    seed = secrets.randbelow(2**MAX_SEED_BITS)
    binary_seed = int2ba(seed) # set value
    seed_ba[-len(binary_seed):] = binary_seed

    size_ba = bitarray(MAX_SIZE_BITS)
    # size = len(size_ba) + len(seed_ba) + len(secret_ba)
    size = len(secret_ba)
    binary_size = int2ba(size) # size of entire payload (including itself)
    size_ba[-len(binary_size):] = binary_size

    metadata_ba = size_ba + seed_ba

    print(f"Seed: {seed} ({seed_ba})")
    print(f"Size: {size} ({size_ba})")
    print(f"Secret {secret} ({secret_ba})")

    # image
    image = Image.open(file)
    width, height = image.size
    pixels = image.load()

        
    def write_to_loc(image, pixels, idx, b, log=False):
        def hide(n, b):
            if b == 0:
                return n & (254) # last bit = 0
            else:
                return n | (1) # last bit = 1
            
        total_bands = len(image.getbands())
        width, _ = image.size
        x = (idx // total_bands) % width
        y = (idx // total_bands) // width
        band = idx % 3

        pixel = image.getpixel((x, y))
        pixels[x, y] = tuple([x if i != band else hide(x, b) for i,x in enumerate(pixel)])

    # write metadata
    total_size = width * height * len(image.getbands())

    print(total_size)
    
    for i, loc in enumerate(range(total_size - len(metadata_ba), total_size)):
        write_to_loc(image, pixels, loc, metadata_ba[i], log=True)

    # write body
    random.seed(seed)

    rand_locs = []

    for b in secret_ba:
        loc = random.randrange(0, total_size - len(metadata_ba) - 1)
        rand_locs.append(loc)
        write_to_loc(image, pixels, loc, b)

    print(rand_locs)

    # save the file
    image.save('MOD_' + file, format='png')

    return "MOD_" + file


def discover(file):
    image = Image.open(file)
    width, height = image.size

    def read_from_loc(image, idx):
        total_bands = len(image.getbands())
        width, _ = image.size
        x = (idx // total_bands) % width
        y = (idx // total_bands) // width
        band = idx % 3

        return image.getpixel((x, y))[band] & 1

    # read metadata
    total_size = width * height * len(image.getbands())

    metadata_ba = bitarray(MAX_SIZE_BITS + MAX_SEED_BITS)
    
    for i, loc in enumerate(range(total_size - len(metadata_ba), total_size)):
        metadata_ba[i] = read_from_loc(image, loc)

    size = ba2int(metadata_ba[:MAX_SIZE_BITS])
    seed = ba2int(metadata_ba[-MAX_SEED_BITS:])

    # read body
    random.seed(seed)

    rand_locs = []

    payload_ba = bitarray(size)
    for i in range(len(payload_ba)):
        loc = random.randrange(0, total_size - len(metadata_ba) - 1)
        rand_locs.append(loc)
        payload_ba[i] = read_from_loc(image, loc)

    try:
        return payload_ba.tobytes().decode("utf8")
    except:
        return None
    

secret = "TEST"
file = "grizzly_bear.png"
new_f = enscribe(file, secret)
print(discover(new_f))