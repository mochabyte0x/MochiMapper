#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author                    : B0lg0r0v (Arthur Minasyan)
# Date created              : 18 Sep 2024
# Based on                  : HellShell (MalDev Academy)

import os
import math
import socket
import string
import random

from base64 import b64encode
from Crypto.Cipher import AES
from argparse import ArgumentParser
from Crypto.Util.Padding import pad

from Core.utils import Colors, banner


#--------------- Encryption Methods ---------------#

# Simple XOR encryption
def xor_encrypt(data):
    print(Colors.light_blue("[+] Encryption Technique:\tXOR"))
    
    def generate_random_key(length=16):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    key = generate_random_key()
    print(Colors.light_yellow(f"[+] Key (raw):\t\t\t{key}\n"))

    output_data = bytearray()
    
    for i, byte in enumerate(data):
        output_data.append(byte ^ ord(key[i % len(key)]))

    
    # Convert bytearray to hex format and print
    #hex_content = ', '.join([f'0x{byte:02x}' for byte in output_data])
    #c_code = f'\nchar key[] = {{{hex_content}}};'
    #print(c_code)
    
    return output_data

# Generate a random KEY and IV
def generate_key_and_iv(key_size):
    # Generate a 16-byte or 32-byte key for AES-128 or AES-256
    key = os.urandom(key_size)
    #print(key)
    # Generate a 16-byte IV (128 bits, which is the block size for AES)
    iv = os.urandom(AES.block_size)
    #print(iv)
    
    return key, iv

# AES-256 CBC encryption
def aes_encrypt(shellcode):
    print(Colors.light_blue("[+] Encryption Technique:\tAES-256-CBC"))
    
    # Generate random key and IV
    key, iv = generate_key_and_iv(32)
    
    # Print the key and IV
    print(Colors.light_yellow(f"[+] Key (hex):\t\t\t{'0x' + ', 0x'.join([key.hex()[i:i+2] for i in range(0, len(key.hex()), 2)])}"))
    print(Colors.light_yellow(f"[+] IV (hex):\t\t\t{'0x' + ', 0x'.join([iv.hex()[i:i+2] for i in range(0, len(iv.hex()), 2)])}\n"))
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the shellcode to be a multiple of 16 bytes (AES block size)
    padded_shellcode = pad(shellcode, AES.block_size)
    
    # Encrypt the padded shellcode
    enc_shellcode = cipher.encrypt(padded_shellcode)
    
    # Return the encrypted shellcode
    return enc_shellcode

# AES-128 CBC encryption
def aes_encrypt_128(shellcode):
    print(Colors.light_blue("[+] Encryption Technique:\tAES-128-CBC"))

    # Generate random key and IV
    key, iv = generate_key_and_iv(16)

    # Print the key and IV
    print(Colors.light_yellow(f"[+] Key (hex):\t\t\t{'0x' + ', 0x'.join([key.hex()[i:i+2] for i in range(0, len(key.hex()), 2)])}"))
    print(Colors.light_yellow(f"[+] IV (hex):\t\t\t{'0x' + ', 0x'.join([iv.hex()[i:i+2] for i in range(0, len(iv.hex()), 2)])}\n"))

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the shellcode to be a multiple of 16 bytes (AES block size)
    padded_shellcode = pad(shellcode, AES.block_size)

    # Encrypt the padded shellcode
    enc_shellcode = cipher.encrypt(padded_shellcode)

    # Return the encrypted shellcode
    return enc_shellcode


#--------------------------------------------------#

#--------------- Entropy Reducer ---------------#
def reducer(shellcode):
    # Calculating the entropy of the payload
    entropy = 0
    for byte in set(shellcode):
        p_x = shellcode.count(byte) / len(shellcode)
        entropy += - p_x * math.log2(p_x)

    print(Colors.light_blue(f"[i] Entropy of the payload: \t{entropy}"))

    # Checking the size of the payload. Depending on how big it is, we will reduce it by a certain amount of bytes.
    if len(shellcode) < 1000:
        amount = random.randint(500, 1000)

    elif len(shellcode) < 2000:
        amount = random.randint(2000, 4000)

    elif len(shellcode) < 4000:
        amount = random.randint(4000, 8000)

    # Padding to the end of the payload to reduce the entropy
    padding = b'\xFC' * amount
    shellcode += padding

    # Calculating the entropy of the reduced payload
    entropy = 0
    for byte in set(shellcode):
        p_x = shellcode.count(byte) / len(shellcode)
        entropy += - p_x * math.log2(p_x)
    
    print(Colors.green(f"[i] New entropy of the payload: {entropy}"))
    print(Colors.light_yellow(f"[i] Payload reduced by: \t{amount} bytes"))

    # Return the modified shellcode
    return shellcode


#--------------------------------------------------#

#--------------- Obfuscation Methods ---------------#

# IPv4 Obfuscation
def ipv4_obfuscation(shellcode):
    # We parse through the shellcode and select every time 4 bytes (ex. C0A832A5). 
    # We also need to ensure that the shellcode is a multiple of 4 bytes, so we pad it if it's not.
    # Then we convert them into their decimal equivalent (in this case 192.168.50.165).
    # It always needs to be in a IPv4 format, so 4 octets are needed every time.

    print(Colors.light_blue("[+] Obfuscation Technique:\tIPv4Fuscation"))
    obfuscated_shellcode = []
    
    # Checking if the shellcode is a multiple of 4 bytes
    if len(shellcode) % 4 != 0:

        # Pad the shellcode with NOPs
        shellcode = shellcode + b"\x90" * (4 - len(shellcode) % 4)

    # We go through the shellcode and select every 4 bytes
    for i in range(0, len(shellcode), 4):
        # We convert the 4 bytes into their decimal equivalent
        ip_address = socket.inet_ntoa(shellcode[i:i+4])
        # We add the decimal equivalent to the obfuscated shellcode
        obfuscated_shellcode.append(ip_address)

    #print(obfuscated_shellcode)
    print(Colors.yellow(f"[+] Number of IPv4 Addresses:\t{len(obfuscated_shellcode)}"))
    print(Colors.green("[+] IPv4Fuscation done"))
    return obfuscated_shellcode
  

def ipv6_obfuscation(shellcode):
    # We parse through the shellcode and select every time 4 bytes again.
    # We do not need to convert them, since IPv6 addresses are already in a hexadecimal format.
    # It always needs to be in a IPv6 format, so 8 groups of 2 hexadecimal digits are needed every time.
    print(Colors.light_blue("[+] Obfuscation Technique:\tIPv6Fuscation"))

    obfuscated_shellcode = []

    if len(shellcode) % 16 != 0:
        # We pad the shellcode with 0
        shellcode = shellcode + b"\x00" * (16 - len(shellcode) % 16)

    for i in range(0, len(shellcode), 16):
        ipv6_str = ':'.join([shellcode[i+j:i+j+2].hex() for j in range(0, 16, 2)])
        #ip_address = socket.inet_pton(socket.AF_INET6, ipv6_str)
        obfuscated_shellcode.append(ipv6_str)

    print(Colors.yellow(f"[+] Number of IPv6 Addresses:\t{len(obfuscated_shellcode)}"))
    print(Colors.green("[+] IPv6Fuscation done"))
    return obfuscated_shellcode



def mac_obfuscation(shellcode):
    # We do similar to IPv6. This time, the shellcode should be a multiple of 6.
    print(Colors.light_blue("[+] Obfuscation Technique:\tMACFuscation"))

    obfuscated_shellcode = []

    if len(shellcode) % 6 != 0:
        # We pad the shellcode with 0
        shellcode = shellcode + b"\x00" * (6 - len(shellcode) % 6)

    # We go through the shellcode and select every 6 bytes. Every 2 bytes should be the delimiter with the colon.
    # We convert the 6 bytes into their decimal equivalent.
    for i in range(0, len(shellcode), 6):
        mac_str = '-'.join([shellcode[i+j:i+j+1].hex() for j in range(6)])
        obfuscated_shellcode.append(mac_str)

    print(Colors.yellow(f"[+] Number of MAC Addresses:\t{len(obfuscated_shellcode)}"))
    print(Colors.green("[+] MACFuscation done"))
    
    return obfuscated_shellcode
        

def uuid_obfuscation(shellcode):
    # The UUID is a bit more complicated. We need to split the shellcode into 5 sections.
    # Section 1: is made out of 4 bytes, which are in little endian format. So ex. C0A832A5 will be A532C0A8. 
    # Section 2: is made out of 2 bytes, which are in little endian format. So ex. C0A8 will be A8C0.
    # Section 3: is made out of 2 bytes, which are in little endian format. 
    # Section 4: is made out of 2 bytes, which are in big endian format. So ex. C0A832A50000 will still be C0A832A50000.
    # Section 5: is made out of 6 bytes, which are in big endian format. 
    # We then concatenate the sections and add the dashes to get the final UUID.

    print(Colors.light_blue("[+] Obfuscation Technique:\tUUIDFuscation"))

    obfuscated_shellcode = []

    if len(shellcode) % 16 != 0:
        # We pad the shellcode with 0
        shellcode = shellcode + b"\x00" * (16 - len(shellcode) % 16)

    for i in range(0, len(shellcode), 16):
        section1 = shellcode[i:i+4][::-1].hex()
        section2 = shellcode[i+4:i+6][::-1].hex()
        section3 = shellcode[i+6:i+8][::-1].hex()
        section4 = shellcode[i+8:i+10].hex()
        section5 = shellcode[i+10:i+16].hex()

        uuid_str = f"{section1}-{section2}-{section3}-{section4}-{section5}"
        obfuscated_shellcode.append(uuid_str)

    print(Colors.yellow(f"[+] Number of UUIDs:\t\t{len(obfuscated_shellcode)}"))
    print(Colors.green("[+] UUIDFuscation done"))
    return obfuscated_shellcode


#--------------------------------------------------#

#--------------- Utils ---------------#

# Reconstruction of the C/C++ ready code
def reconstruct_shellcode(obfuscated_shellcode):
    # We go through the list and print in out in a C/C++ ready format
    print(Colors.yellow("\n[+] Reconstructing the shellcode"))
    
    if isinstance(obfuscated_shellcode, list):
        shellcode_str = '","'.join(obfuscated_shellcode)
        shellcode_str = f'char* shellcode[] = {{"{shellcode_str}"}};'
    
    elif isinstance(obfuscated_shellcode, bytearray):
        shellcode_str = ', '.join([f'0x{byte:02x}' for byte in obfuscated_shellcode])
        shellcode_str = f'unsigned char shellcode[] = {{{shellcode_str}}};'

    elif isinstance(obfuscated_shellcode, bytes):
        shellcode_str = ', '.join([f'0x{byte:02x}' for byte in obfuscated_shellcode])
        shellcode_str = f'unsigned char shellcode[] = {{{shellcode_str}}};'

    print(Colors.green("[+] Shellcode reconstructed\n"))
    print(shellcode_str)
    return shellcode_str

def output_shellcode(file_name, shellcode_str):
       
    current_path = os.getcwd()

    with open(f"{current_path}/{file_name}.bin", "wb") as f:
        f.write(shellcode_str)

    print(Colors.green(f"[+] Encrypted shellcode saved as {file_name}.bin"))
    exit(0)
    

#--------------------------------------------------#

def main():
    # Initializing the parser
    parser = ArgumentParser(description="ObfusX is a simple utility to support you in creating a obfuscated payload. It can use IPv4 / IPv6Fuscation, MACFuscation and UUIDFuscation in conjuction with XOR / AES encryption to obfuscate the shellcode.")

    # Adding the arguments
    parser.add_argument("-v", "--version", action="version", version="ObfusX 1.0")
    parser.add_argument("-p", "--payload", required=True, help="The payload as a raw file")
    parser.add_argument("-enc", "--encryption", help="The encryption method (xor or aes-128/256)")
    parser.add_argument("-obf", "--obfuscation", help="The obfuscation method (ipv4, ipv6, mac or uuid)")
    parser.add_argument("-r", "--reducer", action="store_true", help="Reduce the entropy of the payload. Only supported with '-o' flag. See output flag for more information")
    parser.add_argument("-o", "--output", help="Save the new payload as a raw binary file. Only supported with encryption and no obfuscation methods")

    # Parse the arguments
    args = parser.parse_args()

    # Banner ofc !
    banner()

    # Read the shellcode from the file as bytes
    try:
        # Read the shellcode from the file as bytes
        with open(args.payload, "rb") as f:
            shellcode = f.read()
    except Exception as e:
        print(Colors.red(f"[-] Error reading the payload: {e}"))
        exit(1)

    # Arguments stuff
    if args.payload:

        if args.output is None:

            if args.encryption is None:

                if args.obfuscation:
                    
                    if args.obfuscation.lower() == "ipv4":

                        reconstruct_shellcode(ipv4_obfuscation(shellcode))

                    if args.obfuscation.lower() == "ipv6":

                        reconstruct_shellcode(ipv6_obfuscation(shellcode))

                    if args.obfuscation.lower() == "mac":

                        reconstruct_shellcode(mac_obfuscation(shellcode))

                    if args.obfuscation.lower() == "uuid":

                        reconstruct_shellcode(uuid_obfuscation(shellcode))
        
            if args.encryption:

                if args.encryption.lower() == "xor":

                    if args.obfuscation:

                        if args.obfuscation.lower() == "ipv4":

                            reconstruct_shellcode(ipv4_obfuscation(xor_encrypt(shellcode)))

                        if args.obfuscation.lower() == "ipv6":

                            reconstruct_shellcode(ipv6_obfuscation(xor_encrypt(shellcode)))

                        if args.obfuscation.lower() == "mac":


                            reconstruct_shellcode(mac_obfuscation(xor_encrypt(shellcode)))

                        if args.obfuscation.lower() == "uuid":

                            reconstruct_shellcode(uuid_obfuscation(xor_encrypt(shellcode)))

                    if args.obfuscation is None:

                        reconstruct_shellcode(xor_encrypt(shellcode))
            
                if args.encryption.lower() == "aes-256":

                    if args.obfuscation:

                        if args.obfuscation.lower() == "ipv4":

                            reconstruct_shellcode(ipv4_obfuscation(aes_encrypt(shellcode)))

                        if args.obfuscation.lower() == "ipv6":

                            reconstruct_shellcode(ipv6_obfuscation(aes_encrypt(shellcode)))

                        if args.obfuscation.lower() == "mac":

                            reconstruct_shellcode(mac_obfuscation(aes_encrypt(shellcode)))

                        if args.obfuscation.lower() == "uuid":

                            reconstruct_shellcode(uuid_obfuscation(aes_encrypt(shellcode)))

                    if args.obfuscation is None:

                        reconstruct_shellcode(aes_encrypt(shellcode))

                if args.encryption.lower() == "aes-128":

                    if args.obfuscation:

                        if args.obfuscation.lower() == "ipv4":

                            reconstruct_shellcode(ipv4_obfuscation(aes_encrypt_128(shellcode)))

                        if args.obfuscation.lower() == "ipv6":

                            reconstruct_shellcode(ipv6_obfuscation(aes_encrypt_128(shellcode)))

                        if args.obfuscation.lower() == "mac":

                            reconstruct_shellcode(mac_obfuscation(aes_encrypt_128(shellcode)))

                        if args.obfuscation.lower() == "uuid":

                            reconstruct_shellcode(uuid_obfuscation(aes_encrypt_128(shellcode)))

                    if args.obfuscation is None:

                        reconstruct_shellcode(aes_encrypt_128(shellcode))

        
        if args.output:

            if args.encryption is None:

                if args.obfuscation: 

                    print(Colors.red("[-] Output is supported only with encryption methods and no obfuscation methods"))

                if args.reducer:

                    output_shellcode(args.output, reducer(shellcode))
            
            if args.encryption:

                if args.reducer: 

                    if args.encryption.lower() == "xor":

                        output_shellcode(args.output, reducer(xor_encrypt(shellcode)))

                    if args.encryption.lower() == "aes-256":
                        
                        output_shellcode(args.output, reducer(aes_encrypt(shellcode)))

                    if args.encryption.lower() == "aes-128":

                        output_shellcode(args.output, reducer(aes_encrypt_128(shellcode)))

                if args.reducer is False:

                    if args.encryption.lower() == "xor":

                        output_shellcode(args.output, xor_encrypt(shellcode))

                    if args.encryption.lower() == "aes-256":

                        output_shellcode(args.output, aes_encrypt(shellcode))

                    if args.encryption.lower() == "aes-128":

                        output_shellcode(args.output, aes_encrypt_128(shellcode))
          

    else:
        print(Colors.red("[-] No payload or encryption method or obfuscation method provided"))
        exit(1)


if __name__ == "__main__":

    main()
