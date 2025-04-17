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
from bitarray.util import ba2int
from pathlib import Path
import io

class Steganographer:
    def __init__(self):
        self.MAX_SIZE_BITS = 16
        self.filepath : Path = None
        pass

    def set_file(self, filepath : Path):
        self.filepath = filepath

    def enscribe(self, file, secret):
        def binary(x):
            return format(x, '08b')
        secret = secret.encode('utf8')

        s_bits = bitarray(''.join([binary(c) for c in secret]))

        s_size_bits = bitarray(self.MAX_SIZE_BITS)
        s_size_bits_val = bitarray(binary(len(s_size_bits) + len(s_bits))) # size of entire payload (including itself)
        s_size_bits[-len(s_size_bits_val):] = s_size_bits_val

        total_msg_bits = s_size_bits + s_bits
        total_msg_bits_len = len(total_msg_bits)

        # image
        img = Image.open(file)
        pixels = img.load()
        width, height = img.size

        bit_idx = 0
        pixel_idx = 0
        while bit_idx < total_msg_bits_len:

            def hide(n, b):
                if b == 0:
                    return n & (254) # last bit = 0
                else:
                    return n | (1) # last bit = 1
                
            x = pixel_idx % width
            y = pixel_idx // width
            pixel_channels = img.getpixel((x, y))

            new_channel = list()

            for channel_val in pixel_channels:
                if bit_idx < total_msg_bits_len:
                    new_channel.append(hide(channel_val, total_msg_bits[bit_idx]))
                    bit_idx = bit_idx + 1
                else:
                    new_channel.append(channel_val)

            pixels[x, y] = tuple(new_channel)
            pixel_idx = pixel_idx + 1
            
        image_bytes = io.BytesIO()
        img.save(image_bytes, format='png')
        return image_bytes.getvalue()
        # new_f = "MOD_" + file
        # img.save(new_f, format='png')
        # return new_f
    
    def discover(self, file):
        img = Image.open(file)
        width, height = img.size
        
        # read size
        bit_idx = 0
        pixel_idx = 0

        payload_size = bitarray()

        while bit_idx < self.MAX_SIZE_BITS:        
            x = pixel_idx % width
            y = pixel_idx // width
            pixel_channels = img.getpixel((x, y))

            for channel_val in pixel_channels:
                if bit_idx < self.MAX_SIZE_BITS:
                    payload_size.append(channel_val & 1)
                else:
                    break
                bit_idx = bit_idx + 1
            
            pixel_idx = pixel_idx + 1

        payload_size = ba2int(payload_size)

        # REMOVE

        # read payload
        bit_idx = 0
        pixel_idx = 0

        payload = bitarray()

        while bit_idx < payload_size:        
            x = pixel_idx % width
            y = pixel_idx // width
            pixel_channels = img.getpixel((x, y))

            for channel_val in pixel_channels:
                if bit_idx < payload_size:
                    payload.append(channel_val & 1)
                else:
                    break
                bit_idx = bit_idx + 1
            
            pixel_idx = pixel_idx + 1
        
        payload_text_bits = payload[self.MAX_SIZE_BITS:]
        try:
            payload_text = payload_text_bits.tobytes().decode("utf8")
        except:
            payload_text = None

        return payload_text

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