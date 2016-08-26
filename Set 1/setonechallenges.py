import sys
import array
import base64
import json
import re #used in Set 1, Challenge 4

#================ Set 1, Challenge 1 ==================
def hex_to_64(hex):
    hex_data = hex.decode("hex")
    result = base64.b64encode(hex_data)
        
    return result
        
#================ Set 1, Challenge 2 ================== 
def fixed_xor(hex_one,hex_two): 
    hex_data_one = int(hex_one,16)
    hex_data_two = int(hex_two,16)
    
    long_result = hex_data_one ^ hex_data_two
    
    hex_result = "{0:#0{1}x}".format(long_result,len(hex_one)+2)
    return hex_result[2:]

#================ Set 1, Challenge 3 ================== 
def single_byte_xor_cipher(hex):
    hex_data = hex.decode("hex")
    
    num_xor_to_check = 128
    success_each_xor = [None] * num_xor_to_check
    
    for cipher_test in range(0,num_xor_to_check):
        byte_array = bytearray(hex_data)
        ascii_array = []
        string_result_arr = []
        for index in range(0, len(byte_array)):
            new_char = byte_array[index]^cipher_test
            ascii_array.append(new_char)
            
        success_each_xor[cipher_test] = check_score_english_frequency(ascii_array)
        string_result = stringify_ascii_array(ascii_array)

#    Iterate over success_each_xor and return the top ranking one 
    min_score = min(success_each_xor)
    index_of_min = success_each_xor.index(min(success_each_xor))

#    Re-xor the right string (hopefully!)
    byte_array = bytearray(hex_data)
    ascii_array = []
    string_result_arr = []
    for index in range(0, len(byte_array)):
        new_char = byte_array[index]^index_of_min
        ascii_array.append(new_char)
        
    string_result = stringify_ascii_array(ascii_array)

    return string_result,min_score
    
#================ Set 1, Challenge 4 ================== 
def detect_single_char_xor(file_to_test):
    with open(file_to_test) as data_file:    
        hex_data = data_file.readlines()
        
    array_of_scores_each = []
    
    for index in range(0,len(hex_data)): 
        #Remove spaces from hex data
        hex_data[index] = re.sub('[^0-9a-zA-Z]+', '', hex_data[index])
        array_of_scores_each.append(single_byte_xor_cipher(hex_data[index])[1])
        
    min_score = min(array_of_scores_each)
    index_of_min = array_of_scores_each.index(min_score)
    
    result = single_byte_xor_cipher(hex_data[index_of_min])[0] 
    #Remove any new line instructions etc
    result = re.sub('[^0-9a-zA-Z ]+', '', result)
    
    return result,min_score

#================ Set 1, Challenge 5 ================== 
def implement_repeating_key_xor(file_to_encrypt,key):
    with open(file_to_encrypt) as data_file: 
        text_list = data_file.readlines()
    text = ''.join(text_list)
         
    hex_of_text = text.encode("hex")
    hex_of_key = key.encode("hex")
    full_key_list = []
    
    index_of_key = 0
    for index in range(0,len(hex_of_text)):
        if (index_of_key == len(hex_of_key)):
            index_of_key = 0
        full_key_list.append(hex_of_key[index_of_key])
        index_of_key += 1
    
    full_key = ''.join(full_key_list)
    
    hex_encrypted = fixed_xor(hex_of_text,full_key);
    return hex_encrypted;
    
def unencrypt_repeating_key_xor(hex_str,key_ascii):
    hex_of_text = hex_str
    hex_of_key = key_ascii.encode("hex")
    full_key_list = []
    
    index_of_key = 0
    for index in range(0,len(hex_of_text)):
        if (index_of_key == len(hex_of_key)):
            index_of_key = 0
        full_key_list.append(hex_of_key[index_of_key])
        index_of_key += 1
    
    full_key = ''.join(full_key_list)
    
    hex_unencrypted = fixed_xor(hex_of_text,full_key);
    return hex_unencrypted;
    
#================ Set 1, Challenge 6 ================== 
def break_repeating_key_xor(file_to_break):
    str_encryption = read_file(file_to_break)
    hex_of_data = b64_to_hex(str_encryption)
    total_byte_array = bytearray.fromhex(hex_of_data)
    
    ranked_list_keysizes = get_ranked_key_lengths(total_byte_array)
    grouped_byte_arr = group_repeat_key(total_byte_array,ranked_list_keysizes[0][0])
    
    grouped_hex_arr = []
    for index in range (0,len(grouped_byte_arr)):
        grouped_hex_arr.append(byte_array_to_hex(grouped_byte_arr[index]))
        
    cracked_hex_arr = []
    for index in range (0,len(grouped_hex_arr)):
        cracked_hex_arr.append(single_byte_xor_cipher(grouped_hex_arr[index])[0])
    
    cracked_str = re_order_grouped_list(cracked_hex_arr)

    print cracked_str
    
def re_order_grouped_list(unicode_list):
    ordered_str = ''
    key_length = len(unicode_list)
    
    for letter_index in range(0,len(unicode_list[0])):
        for group_index in range(0,key_length):
            if (len(unicode_list[group_index]) > letter_index):
                ordered_str += unicode_list[group_index][letter_index]                
            
    return ordered_str
    
def group_repeat_key(total_byte_array,key_length):
    list_grouped_byte_arr = [bytearray]*key_length
    
#    Create group of same cypher 
    list_byte_arr = []
    for groupNumber in range(0,key_length): 
        group = bytearray()
        for index in range(0,len(total_byte_array)/key_length):
            group.append(total_byte_array[(index*key_length)+groupNumber])
        
        list_byte_arr.append(group) 
           
    return list_byte_arr    
         

def get_ranked_key_lengths(total_byte_array):
    norm_hamm_diffs = []
    max_keysize = 40
    
    for test_keysize in range(2,max_keysize+1):
        total_hamm_diffs = 0
        num_hamm_diffs = 0
        for loop_byte in range(0,(len(total_byte_array)/test_keysize)-test_keysize):
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

#================ USEFUL FUNCTIONS ================== 
    
# FUNCTION CHECKS HOW WELL IT MATCHES TO THE FREQUENCY OF CHARACTERS IN ENGLISH PLAINTEXT
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
    
def stringify_ascii_array(ascii_array): 
    string_arr = []
    for character in ascii_array:
        string_arr.append(unichr(character))
    
    return ''.join(string_arr)
    
def compute_hamming_distance(byte_arr_one,byte_arr_two):
    num_differing_bits = 0

    for index in range(0,len(byte_arr_one)):
        differing_bits = byte_arr_one[index] ^ byte_arr_two[index]
        num_differing_bits += bin(differing_bits).count("1")
    
    return num_differing_bits

def b64_to_hex(base64_str):
    decoded_data = base64_str.decode("base64")
    result = decoded_data.encode("hex")
        
    return result
    
def read_file(file_to_read):
    with open(file_to_read) as data_file: 
        text_list = data_file.readlines()
    
    return ''.join(text_list)    

def byte_array_to_hex(byte_array):
    return ''.join(format(x, '02x') for x in byte_array)
        
  
if __name__ == "__main__":        
#    print b64_to_hex(read_file("TestInputFiles/Set1Challenge6SuppliedFile.txt"))
    break_repeating_key_xor('TestInputFiles/Set1Challenge6SuppliedFile.txt')    
    
    
    
    
   
        