from PIL import Image
from bitarray import bitarray
from bitarray.util import ba2int, int2ba
from pathlib import Path
import io
import secrets
import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAX_SEED_BITS = 16
MAX_SIZE_BITS = 17
IV_BYTES = 16
SALT_BYTES = 16
BLOCK_SIZE_BITS = 128

def encrypt(password: bytes, plaintext: bytes):
    # 0. pad plaintext
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    plaintext = padder.update(plaintext) + padder.finalize()

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

    # 3. unpad plaintext
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()

    return plaintext



def enscribe(file, secret, password):
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
    print(f"(ENCRYPT) Metadata: {metadata_ba}")

    print(f"(ENCRYPT) Seed: {seed} ({seed_ba})")
    print(f"(ENCRYPT) Size: {size} ({size_ba})")
    print(f"(ENCRYPT) Secret {secret} ({secret_ba})")

    salt, iv, ciphertext = encrypt(bytes(password, encoding='utf8'), metadata_ba.tobytes())

    enc_metadata_ba = bitarray()
    enc_metadata_ba.frombytes(ciphertext + iv + salt)

    print(f"(ENCRYPT) Encrypted Metadata: {ciphertext} ({len(ciphertext)})")
    print(f"(ENCRYPT) IV: {iv} ({len(iv)})")
    print(f"(ENCRYPT) Salt: {salt} ({len(salt)})")
    print(f"(ENCRYPT) Encrypted Metadata Group (bytes): {enc_metadata_ba.tobytes()} ({len(enc_metadata_ba.tobytes())})")
    print(f"(ENCRYPT) Encrypted Metadata Group (bits): {enc_metadata_ba} ({len(enc_metadata_ba)})")

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
    
    for i, loc in enumerate(range(total_size - len(enc_metadata_ba), total_size)):
        write_to_loc(image, pixels, loc, enc_metadata_ba[i], log=True)

    # write body
    random.seed(seed)

    rand_locs = []

    for b in secret_ba:
        loc = random.randrange(0, total_size - len(enc_metadata_ba) - 1)
        rand_locs.append(loc)
        write_to_loc(image, pixels, loc, b)

    # save the file
    image.save('MOD_' + file, format='png')

    return "MOD_" + file


def discover(file, password):
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

    enc_metadata_ba = bitarray(BLOCK_SIZE_BITS + (IV_BYTES + SALT_BYTES) * 8)
    
    for i, loc in enumerate(range(total_size - len(enc_metadata_ba), total_size)):
        enc_metadata_ba[i] = read_from_loc(image, loc)

    print(enc_metadata_ba)
    ciphertext = enc_metadata_ba[:BLOCK_SIZE_BITS].tobytes()
    iv = enc_metadata_ba[BLOCK_SIZE_BITS:BLOCK_SIZE_BITS + (IV_BYTES * 8)].tobytes()
    salt = enc_metadata_ba[BLOCK_SIZE_BITS + (IV_BYTES * 8):].tobytes()

    print(f"(DECRYPT) Encrypted Metadata: {ciphertext} ({len(ciphertext)})")
    print(f"(DECRYPT) IV: {iv} ({len(iv)})")
    print(f"(DECRYPT) Salt: {salt} ({len(salt)})")
    print(f"(DECRYPT) Encrypted Metadata Group (bytes): {enc_metadata_ba.tobytes()} ({len(enc_metadata_ba.tobytes())})")
    print(f"(DECRYPT) Encrypted Metadata Group (bits): {enc_metadata_ba} ({len(enc_metadata_ba)})")
    
    plaintext = decrypt(bytes(password, encoding='utf8'), salt, ciphertext, iv)

    metadata_ba = bitarray()
    metadata_ba.frombytes(plaintext)

    size = ba2int(metadata_ba[:MAX_SIZE_BITS])
    seed = ba2int(metadata_ba[MAX_SIZE_BITS:MAX_SIZE_BITS + MAX_SEED_BITS]) # ending will be padding up to block size 

    print(f"(DECRYPT) Metadata: {metadata_ba}")

    print(f"(DECRYPT) Seed: {seed} ({seed})")
    print(f"(DECRYPT) Size: {size} ({size})")

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
    

secret = "TESTING TESTING"
file = "grizzly_bear.png"
new_f = enscribe(file, secret, "dobeedo")
print(discover(new_f, "dobeedo"))