from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMainWindow,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QWidget,
    QFileDialog,
    QInputDialog
)
from PySide6.QtGui import (
    QPixmap
)
from PySide6.QtCore import  QSize, Qt, QByteArray
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

class Steganographer:
    def __init__(self):
        self.MAX_SIZE_BITS = 16
        self.MAX_SEED_BITS = 16
        self.IV_BYTES = 16
        self.SALT_BYTES = 16
        self.BLOCK_SIZE_BITS = 128
        self.filepath : Path = None
        pass

    def set_file(self, filepath : Path):
        self.filepath = filepath

    def encrypt(self, password: bytes, plaintext: bytes):
        # 0. pad plaintext
        padder = padding.PKCS7(self.BLOCK_SIZE_BITS).padder()
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

    def decrypt(self, password: bytes, salt: bytes, ciphertext: bytes, iv: bytes):
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
        unpadder = padding.PKCS7(self.BLOCK_SIZE_BITS).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return plaintext



    def enscribe(self, file, secret, password):
        def binary(x):
            return format(x, '08b')
        secret = secret.encode('utf8')

        secret_ba = bitarray(''.join([binary(c) for c in secret]))

        # used to seed RNG for bit placement
        seed_ba = bitarray(self.MAX_SEED_BITS)
        seed = secrets.randbelow(2**self.MAX_SEED_BITS)
        binary_seed = int2ba(seed) # set value
        seed_ba[-len(binary_seed):] = binary_seed

        size_ba = bitarray(self.MAX_SIZE_BITS)
        # size = len(size_ba) + len(seed_ba) + len(secret_ba)
        size = len(secret_ba)
        binary_size = int2ba(size) # size of entire payload (including itself)
        size_ba[-len(binary_size):] = binary_size

        metadata_ba = size_ba + seed_ba

        salt, iv, ciphertext = self.encrypt(bytes(password, encoding='utf8'), metadata_ba.tobytes())

        enc_metadata_ba = bitarray()
        enc_metadata_ba.frombytes(ciphertext + iv + salt)

        # image
        image = Image.open(file)
        width, height = image.size
        pixels = image.load()

        print(f"Image Size (bits): {width * height * len(image.getbands())}")
        print(f"Message Size: {size}")
        print(f"Proportion: {round(size / (width * height * len(image.getbands())), 2)}")
            
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
        image_bytes = io.BytesIO()
        image.save(image_bytes, format='png')

        return image_bytes.getvalue()


    def discover(self, file, password):
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

        enc_metadata_ba = bitarray(self.BLOCK_SIZE_BITS + (self.IV_BYTES + self.SALT_BYTES) * 8)
        
        for i, loc in enumerate(range(total_size - len(enc_metadata_ba), total_size)):
            enc_metadata_ba[i] = read_from_loc(image, loc)

        ciphertext = enc_metadata_ba[:self.BLOCK_SIZE_BITS].tobytes()
        iv = enc_metadata_ba[self.BLOCK_SIZE_BITS:self.BLOCK_SIZE_BITS + (self.IV_BYTES * 8)].tobytes()
        salt = enc_metadata_ba[self.BLOCK_SIZE_BITS + (self.IV_BYTES * 8):].tobytes()
        
        plaintext = self.decrypt(bytes(password, encoding='utf8'), salt, ciphertext, iv)

        metadata_ba = bitarray()
        metadata_ba.frombytes(plaintext)

        size = ba2int(metadata_ba[:self.MAX_SIZE_BITS])
        seed = ba2int(metadata_ba[self.MAX_SIZE_BITS:self.MAX_SIZE_BITS + self.MAX_SEED_BITS]) # ending will be padding up to block size 

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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.steg = Steganographer()

        self.setWindowTitle("My App")
        self.setFixedSize(QSize(600, 500))

        self.left_layout = QVBoxLayout()
        
        self.input = QLineEdit()
        self.enscribe_button = QPushButton("Hide")
        self.discover_button = QPushButton("Discover")
        self.search_image_button = QPushButton("Select File")

        self.enscribe_button.setEnabled(False)
        self.discover_button.setEnabled(False)

        self.left_layout.addStretch()
        self.left_layout.addWidget(self.input)
        self.left_layout.addWidget(self.enscribe_button)
        self.left_layout.addWidget(self.discover_button)
        self.left_layout.addWidget(self.search_image_button)
        self.left_layout.addStretch()

        self.input.textEdited.connect(self.enable_enscribe)
        self.search_image_button.clicked.connect(self.search_images)
        self.discover_button.clicked.connect(self.discover)
        self.enscribe_button.clicked.connect(self.enscribe)



        self.right_layout = QVBoxLayout()

        self.image_container = QVBoxLayout()
        self.filename = QLabel("Filename...")
        self.image = QLabel()
        self.hidden_message = QLabel()
        self.hidden_message.setWordWrap(True)

        self.image_container.addStretch()
        self.image_container.addWidget(self.filename)
        self.image_container.addWidget(self.image)
        self.image_container.addWidget(self.hidden_message)
        self.image_container.addStretch()

        self.right_layout.addLayout(self.image_container)

        self.layout = QHBoxLayout()
        self.layout.addLayout(self.left_layout)

        container = QWidget()
        container.setLayout(self.layout)

        self.setCentralWidget(container)

    
    def search_images(self, s):
        filepath, _ = QFileDialog.getOpenFileName(self,
                                               "Select File...",
                                               "/home/ouroboros/Practice/Stenography/",
                                               "Image Files (*.png)")
        filepath = Path(filepath)
        print(filepath.name)
        self.steg.set_file(filepath)
        if self.layout.indexOf(self.right_layout) == -1:
            self.layout.addLayout(self.right_layout)
        if self.input.text() != '':
            self.enscribe_button.setEnabled(True)
        self.discover_button.setEnabled(True)
        self.filename.setText(filepath.name)
        self.image.setPixmap(QPixmap(filepath).scaled(400, 400, aspectMode=Qt.AspectRatioMode.KeepAspectRatio))
        self.hidden_message.setText("")

    def discover(self, s):
        password, ok = QInputDialog.getText(self, "QInputDialog.getText()",
                                "Password:", QLineEdit.Normal)
        if ok and password:
            hidden_message = self.steg.discover(self.steg.filepath, password)
            if hidden_message:
                self.hidden_message.setText("HIDDEN MESSAGE:\n" + hidden_message)
            else:
                self.hidden_message.setText("NO HIDDEN MESSAGE FOUND")
        else:
            print("Failed to prompt password!")
        
    def enable_enscribe(self, s):
        if self.input.text() != '' and not self.image.pixmap().isNull():
            self.enscribe_button.setEnabled(True)
        else:
            self.enscribe_button.setEnabled(False)

    def enscribe(self, s):
        password, ok = QInputDialog.getText(self, "QInputDialog.getText()",
                                "Password:", QLineEdit.Normal)
        if ok and password:
            enscribed_image_bytes_str = self.steg.enscribe(self.steg.filepath, self.input.text(), password)
            enscribed_image_bytes = QByteArray(enscribed_image_bytes_str)
            QFileDialog.saveFileContent(enscribed_image_bytes, "MOD_" + self.steg.filepath.name)
            self.input.setText("")
        else:
            print("Failed to prompt password!")


app = QApplication([])

window = MainWindow()
window.show()

app.exec()