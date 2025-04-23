# Steganography Program

This program can hide a message inside of PNG images.

It randomizes the location of the message's bits throughout the pixels of the image, 
altering them only in the least significant bit of the RGB so that color is not visibly affected.

The randomized locations are determined by a seed fed to Python's RNG. This seed, along with the 
message size is stored AES-128/CBC encrypted at the end of the image (using the same bit hiding scheme
as the message). The user supplies the password to both encrypt and decrypt this metadata (seed, size),
while the message itself is not encrypted (but rather scattered randomly)