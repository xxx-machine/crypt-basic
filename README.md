# crypt-basic
Custom implementations of Extended Vigenère and AES-128 ciphers.
# Description
Just a personal project for the purpose of exploring modern cryptography and becoming more familiar with C itself.
All functions and maths behind the AES encryption process are self implemented. This is a command line utility which accepts input via arguments and stdin.

## Features
- Vigenère and AES-128 encryption/decryption.
- AES has two modes: Electronic Code Book(default) and Cipher Block Chaining (for further pattern elimination)
- AES mode also accepts **any type of file or data** through stdin (pipes/redirects) in the terminal and can output to a specified file though redirection (>)
# Build
Run this in the source folder:

`gcc -o crypt-lib crypt-lib.c`
# Usage

`./crypt-lib <-e/-d> <vig/aes/aes-cbc> <16 byte key/keyword> <plaintext(optional for aes/aes-cbc)> <IV(for aes-cbc)>`

Files can be input/output via redirects:

`./crypt-lib -e aes-cbc dba8557e471eb1dcf508f29351035ae0 7b1c7e73cb8e504813d42737150418d7 < image.png > image-enc.bin`


Input/output can be piped:

`./crypt-lib -d aes-cbc dba8557e471eb1dcf508f29351035ae0 7b1c7e73cb8e504813d42737150418d7 < secret.bin | grep -ir "flag"`

Contents (not raw bytes) of text files can be read:

`cat enc.txt | ./crypt-lib -d aes 31323334353637383930313233343536`
