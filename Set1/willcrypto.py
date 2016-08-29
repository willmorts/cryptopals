import sys
import array
import base64
import json
import re
from Crypto.Cipher import AES

#================ FORMAT CONVERSIONS =====================================
#================ From hex conversions ===================================
def hex_to_byte_array(hex_data):
    hex_data = hex_data.decode("hex")
    return bytearray(hex_data)

def hex_to_64(hex):
    hex_data = hex.decode("hex")
        
    return base64.b64encode(hex_data)

#================ From base64 conversions ================================
def b64_to_hex(base64_str):
    decoded_data = base64_str.decode("base64")        
    return decoded_data.encode("hex")
    
#================ From plaintext conversions =============================
def text_to_byte_array(text_str):
    return bytearray(text_str)   

#================ From bytearray conversions =============================
def byte_array_to_hex(byte_array):
    return ''.join(format(x, '02x') for x in byte_array)

#================ ENCRYPTION FUNCTIONS ===================================
def repeating_key_xor(byte_array_msg,byte_array_key):
    index_of_key = 0
    full_key_list = bytearray()

    for index in range(0,len(byte_array_msg)):
        if (index_of_key == len(byte_array_key)):
            index_of_key = 0
        full_key_list.append(byte_array_key[index_of_key])
        index_of_key += 1
    
    byte_array_encrypted = fixed_xor_byte_array(byte_array_msg,full_key_list);
    return byte_array_encrypted;

def fixed_xor_byte_array(byte_array_one,byte_array_two):
    result = bytearray()
    
    for index in range(0,len(byte_array_one)):
        result.append(byte_array_one[index]^byte_array_two[index])
    
    return result  
    
#================ GENERAL ADMIN FUNCTIONS ================================     
def read_file(file_to_read):
    with open(file_to_read) as data_file: 
        text_list = data_file.readlines()
    
    return ''.join(text_list)    
    
def write_file(file_to_write,string_to_write):
    with open(file_to_write, 'w') as data_file: 
        data_file.write(string_to_write)