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
    
def b64_to_byte_array(base64_str):
    decoded_data = base64_str.decode("base64")
    return bytearray(decoded_data)
    
#================ From plaintext conversions =============================
def text_to_byte_array(text_str):
    return bytearray(text_str)   

#================ From bytearray conversions =============================
def byte_array_to_hex(byte_array):
    return ''.join(format(x, '02x') for x in byte_array)
    
def byte_array_to_text(byte_array):
    return byte_array.decode("utf-8")

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
    
def unencrypt_repeating_key_xor(byte_array_encrypted,byte_array_key):
    index_of_key = 0
    full_key_list = bytearray()

    for index in range(0,len(byte_array_encrypted)):
        if (index_of_key == len(byte_array_key)):
            index_of_key = 0
        full_key_list.append(byte_array_key[index_of_key])
        index_of_key += 1
    
    byte_array_unencrypted = fixed_xor_byte_array(byte_array_encrypted,full_key_list);
    return byte_array_unencrypted;

def fixed_xor_byte_array(byte_array_one,byte_array_two):
    result = bytearray()
    
    for index in range(0,len(byte_array_one)):
        result.append(byte_array_one[index]^byte_array_two[index])
    
    return result  
    
#================ BREAK CIPHER FUNCTIONS =================================
def break_single_byte_xor(byte_array_msg):
    num_xor_to_check = 128
#    In form: (msg,score,index)
    list_xor_msgs_with_scores = []
    
    for cipher_test in range(0,num_xor_to_check):
        byte_arr_result = bytearray()
        ascii_array = []
        string_result_arr = []
        for index in range(0, len(byte_array_msg)):
            new_char = byte_array_msg[index]^cipher_test
            ascii_array.append(new_char)
            byte_arr_result.append(new_char)
              
        list_xor_msgs_with_scores.append((byte_arr_result,check_score_english_frequency(ascii_array),cipher_test))
        
    list_xor_msgs_with_scores.sort(key=lambda tup: tup[1])
        
    return list_xor_msgs_with_scores
    
#    Take array of byte arrays, any of which may be single byte xor encrypted
def detect_single_byte_xor(arr_byte_arr):
    arr_cracked_bytes_scored = []
    
    for index in range(0,len(arr_byte_arr)):
        broken_tuple = break_single_byte_xor(arr_byte_arr[index])[0]
        arr_cracked_bytes_scored.append((broken_tuple[0],broken_tuple[1],index))
    
    #    Sort into ascending order
    arr_cracked_bytes_scored.sort(key=lambda tup: tup[1])

    return arr_cracked_bytes_scored
    
def break_repeating_key_xor(byte_arr_msg):
    ranked_list_keysizes = get_ranked_key_lengths(byte_arr_msg)
    
#    Group into where key would be the same
    grouped_byte_arr = []
    key_length = ranked_list_keysizes[0][0]
    
    for index_key in range(0,key_length):
        grouped_byte_arr.append(bytearray())
        
    for index in range(0,len(byte_arr_msg)):
        group_number = index%key_length
        grouped_byte_arr[group_number].append(byte_arr_msg[index])
  
#    Crack each grouping of the same single byte xor   
    cracked_byte_arr = []
    for index in range (0,len(grouped_byte_arr)):
        cracked_byte_arr.append(break_single_byte_xor(grouped_byte_arr[index])[0][0])

#    Re-order the separated cracked letters into the original order
    ordered_byte_arr = []
    key_length = len(cracked_byte_arr)
    
    for letter_index in range(0,len(cracked_byte_arr[0])):
        for group_index in range(0,key_length):
            if (len(cracked_byte_arr[group_index]) > letter_index):
                ordered_byte_arr.append(cracked_byte_arr[group_index][letter_index])  
    
    result = ''
    
    for element in ordered_byte_arr: 
        result += unichr(element)
    
    return result

def get_ranked_key_lengths(total_byte_array):
    norm_hamm_diffs = []
    max_keysize = 40
    
    for test_keysize in range(2,max_keysize+1):
        total_hamm_diffs = 0
        num_hamm_diffs = 0
        for loop_byte in range(0,(len(total_byte_array)/test_keysize)-1):
            keysize_chunk = loop_byte*test_keysize
            first_byte_arr = total_byte_array[keysize_chunk:(keysize_chunk+test_keysize)]
            second_byte_arr = total_byte_array[(keysize_chunk+test_keysize):(keysize_chunk+(test_keysize*2))]
            hamm_diff = compute_hamming_distance(first_byte_arr,second_byte_arr)
            total_hamm_diffs += hamm_diff
            num_hamm_diffs += 1
        
        if (num_hamm_diffs != 0):
            current_avg_hamm_diffs = total_hamm_diffs/float(num_hamm_diffs)
        else:
            current_avg_hamm_diffs = 0
        
        if (current_avg_hamm_diffs != 0):
            norm_hamm_diffs.append((test_keysize,(current_avg_hamm_diffs/test_keysize)))
        else:
            norm_hamm_diffs.append((test_keysize,8))
#    Sort into ascending order
    norm_hamm_diffs.sort(key=lambda tup: tup[1])
        
    return norm_hamm_diffs
    
def encrypt_AES128ECB(msg,key):
    obj = AES.new(key,AES.MODE_ECB)
    result = obj.encrypt(msg)
    return result    
    
# Both in form of plain text string (different to the rest
def unencrypt_AES128ECB(msg,key):
#    ECB-type by default
    obj = AES.new(key,AES.MODE_ECB)
    
    result = obj.decrypt(msg)
    
    return result
        
def detect_aes_ecb(arr_byte_arr):
#    array of tuples of line number with its score on likely stateless, deterministic encryption
#    in form : [(line_number,score),(line_no,score)]
    likely_aesecb_lines = []
    for index in range(0,len(arr_byte_arr)):
        if (detect_identical_blocks(arr_byte_arr[index],16)):
            likely_aesecb_lines.append(index) 
     
    return likely_aesecb_lines
        
def detect_identical_blocks(byte_arr,block_size = 16):
    for first_loop_byte in range(0,(len(byte_arr)/block_size)-1):
        start_of_first_byte = first_loop_byte*block_size
        first_byte_arr = byte_arr[start_of_first_byte:(start_of_first_byte+block_size)]
        for second_loop_byte in range(first_loop_byte+1,(len(byte_arr)/block_size)):
            start_of_second_byte = second_loop_byte*block_size
            second_byte_arr = byte_arr[start_of_second_byte:(start_of_second_byte+block_size)]
            if first_byte_arr == second_byte_arr:
                return True     
    
    return False
        
#================ GENERAL ADMIN FUNCTIONS ================================  
def check_score_english_frequency(ascii_array):
    experiment_data = {'a': 0.000, 'b': 0.000, 'c': 0.000, 
        'd': 0.000, 'e': 0.000, 'f': 0.000, 'g': 0.000, 'h': 0.000, 
        'i': 0.000, 'j': 0.000, 'k': 0.000, 'l': 0.000, 'm': 0.000,
        'n': 0.000, 'o': 0.000, 'p': 0.000, 'q': 0.000, 'r': 0.000,
        's': 0.000, 't': 0.000, 'u': 0.000, 'v': 0.000, 'w': 0.000,
        'x': 0.000, 'y': 0.000, 'z': 0.000}
    total = 0
    
    with open('UsefulDataFiles/letterFrequencies.json') as data_file:    
        data = json.load(data_file)
    
    for ascii_character in ascii_array:
        character = (unichr(ascii_character))
        if character in experiment_data:
            experiment_data[character] += 1
            total += 1
    
#    Change experiment data to percentages
    if (total != 0):
        for key in experiment_data:
            experiment_data[key] = (experiment_data[key]/total)*100
            
#    Change experiment data to difference from actual percentages
#    (simple just %actual - %experiment, modulus)
    sum_differences = 0
    for key in experiment_data: 
        experiment_data[key] = abs(experiment_data[key] - data[key])
        sum_differences += experiment_data[key]

    return sum_differences 
    
def compute_hamming_distance(byte_arr_one,byte_arr_two):
    num_differing_bits = 0

    for index in range(0,len(byte_arr_one)):
        differing_bits = byte_arr_one[index] ^ byte_arr_two[index]
        num_differing_bits += bin(differing_bits).count("1")
    
    return num_differing_bits
   
def read_file(file_to_read,bool_join=True):
    with open(file_to_read) as data_file: 
        text_list = data_file.readlines()
    
    if (bool_join):
        text_list = ''.join(text_list)
    
    return text_list    
    
def write_file(file_to_write,string_to_write):
    with open(file_to_write, 'w') as data_file: 
        data_file.write(string_to_write)