from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMainWindow,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QWidget,
    QFileDialog
)
from PySide6.QtGui import (
    QImage,
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

class Steganographer:
    def __init__(self):
        self.MAX_SIZE_BITS = 16
        self.MAX_SEED_BITS = 16
        self.filepath : Path = None
        pass

    def set_file(self, filepath : Path):
        self.filepath = filepath

    def enscribe(self, file, secret):
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
        
        for i, loc in enumerate(range(total_size - len(metadata_ba), total_size)):
            write_to_loc(image, pixels, loc, metadata_ba[i], log=True)

        # write body
        random.seed(seed)

        rand_locs = []

        for b in secret_ba:
            loc = random.randrange(0, total_size - len(metadata_ba) - 1)
            rand_locs.append(loc)
            write_to_loc(image, pixels, loc, b)

        # save the file
        image_bytes = io.BytesIO()
        image.save(image_bytes, format='png')

        return image_bytes.getvalue()
    

    def discover(self, file):
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

        metadata_ba = bitarray(self.MAX_SIZE_BITS + self.MAX_SEED_BITS)
        
        for i, loc in enumerate(range(total_size - len(metadata_ba), total_size)):
            metadata_ba[i] = read_from_loc(image, loc)

        size = ba2int(metadata_ba[:self.MAX_SIZE_BITS])
        seed = ba2int(metadata_ba[-self.MAX_SEED_BITS:])

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
        # self.layout.addLayout(self.right_layout)

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

    def discover(self, s):
        hidden_message = self.steg.discover(self.steg.filepath)
        if hidden_message:
            self.hidden_message.setText("HIDDEN MESSAGE:\n" + hidden_message)
        else:
            self.hidden_message.setText("NO HIDDEN MESSAGE FOUND")
        
    def enable_enscribe(self, s):
        if self.input.text() != '' and self.image.pixmap:
            self.enscribe_button.setEnabled(True)
        else:
            self.enscribe_button.setEnabled(False)

    def enscribe(self, s):
        enscribed_image_bytes_str = self.steg.enscribe(self.steg.filepath, self.input.text())
        enscribed_image_bytes = QByteArray(enscribed_image_bytes_str)
        QFileDialog.saveFileContent(enscribed_image_bytes, "MOD_" + self.steg.filepath.name)


app = QApplication([])

window = MainWindow()
window.show()

app.exec()