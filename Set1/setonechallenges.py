import sys
import array
import base64
import json
import re
from Crypto.Cipher import AES
from willcrypto import *

#================ Set 1, Challenge 1 ==================
def set_one_challenge_one(hex):
    return hex_to_64(hex)
        
#================ Set 1, Challenge 2 ================== 
def set_one_challenge_two(hex_one,hex_two):
    byte_array_one = hex_to_byte_array(hex_one)
    byte_array_two = hex_to_byte_array(hex_two)
    return byte_array_to_hex(fixed_xor_byte_array(byte_array_one,byte_array_two))

#================ Set 1, Challenge 3 ================== 
def set_one_challenge_three(hex):
    byte_array_msg = hex_to_byte_array(hex)
    byte_result = break_single_byte_xor(byte_array_msg)[0][0]
    string_result = byte_array_to_text(byte_result)
    
    return string_result
    
#================ Set 1, Challenge 4 ================== 
def set_one_challenge_four(file_to_test):
    hex_data = read_file(file_to_test,False)
    arr_byte_arr = []
        
    for index in range(0,len(hex_data)): 
        hex_data[index] = re.sub('[^0-9a-zA-Z]+', '', hex_data[index]) 
        arr_byte_arr.append(hex_to_byte_array(hex_data[index]))   
    
#    Returns array of tuples of form (broken_byte_array,score,index)
    result = detect_single_byte_xor(arr_byte_arr)[0]
    
    new_result = (byte_array_to_text(result[0]),result[1],result[2])
    return new_result

#================ Set 1, Challenge 5 ================== 
def set_one_challenge_five(file_to_encrypt,key):    
    text = read_file(file_to_encrypt) 
    byte_array_of_text = text_to_byte_array(text)
    byte_array_key = text_to_byte_array(key)
    byte_array_encrypted = repeating_key_xor(byte_array_of_text,byte_array_key)
    return byte_array_to_hex(byte_array_encrypted)
    
def undo_set_one_challenge_five(hex_str,key_ascii):
    byte_arr_text = hex_to_byte_array(hex_str)
    byte_arr_key = text_to_byte_array(key_ascii)
    byte_arr_unencrypted = unencrypt_repeating_key_xor(byte_arr_text,byte_arr_key)
    result = byte_array_to_text(byte_arr_unencrypted)
    return result
    
#================ Set 1, Challenge 6 ================== 
def set_one_challenge_six(file_to_break):
    str_encrypted = read_file(file_to_break)
    hex_of_data = b64_to_hex(str_encrypted)
    byte_arr_msg = hex_to_byte_array(hex_of_data)        
    return break_repeating_key_xor(byte_arr_msg)

#================ Set 1, Challenge 7 ================== 
def set_one_challenge_seven(file,key):
    message = read_file(file)
    message = message.decode("base64")    
    return unencrypt_AES128ECB(message,key)

    
    
    
   
        