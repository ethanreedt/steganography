from PIL import Image
from bitarray import bitarray
from bitarray.util import ba2int

file = 'grizzly_bear.png'
secret = "I AM A GRIZZLY BEAR RRRR BROWN BEAR BROWN BEAR"

MAX_SIZE_BITS = 16

def binary(x):
    return format(x, '08b')

def enscribe(f, s):
    s = s.encode('utf8')
    s_bits = bitarray(''.join([binary(c) for c in s]))

    s_size_bits = bitarray(MAX_SIZE_BITS)
    s_size_bits_val = bitarray(binary(len(s_size_bits) + len(s_bits))) # size of entire payload (including itself)
    s_size_bits[-len(s_size_bits_val):] = s_size_bits_val

    total_msg_bits = s_size_bits + s_bits
    total_msg_bits_len = len(total_msg_bits)

    # image
    img = Image.open(f)
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
        
    new_f = "MOD_" + f
    img.save(new_f, format='png')
    return new_f



def discover(f):
    img = Image.open(f)
    width, height = img.size
    
    # read size
    bit_idx = 0
    pixel_idx = 0

    payload_size = bitarray()

    while bit_idx < MAX_SIZE_BITS:        
        x = pixel_idx % width
        y = pixel_idx // width
        pixel_channels = img.getpixel((x, y))

        for channel_val in pixel_channels:
            if bit_idx < MAX_SIZE_BITS:
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
    
    payload_text_bits = payload[MAX_SIZE_BITS:]
    payload_text = payload_text_bits.tobytes().decode("utf8")

    return payload_text



enscribed_f = enscribe(file, secret)
print(discover(enscribed_f))