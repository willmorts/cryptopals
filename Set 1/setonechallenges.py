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
    
    hex_result = hex_data_one ^ hex_data_two
    
    hex_result = "{0:#0{1}x}".format(hex_result,len(hex_one)+2)
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
    print text_list
         
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

    print hex_encrypted
    return hex_encrypted;

#================ Set 1, Challenges 3 & 4 useful function ================== 
    
# FUNCTION CHECKS HOW WELL IT MATCHES TO THE FREQUENCY OF CHARACTERS IN ENGLISH PLAINTEXT
def check_score_english_frequency(ascii_array):
    experiment_data = {'a': 0.000, 'b': 0.000, 'c': 0.000, 
        'd': 0.000, 'e': 0.000, 'f': 0.000, 'g': 0.000, 'h': 0.000, 
        'i': 0.000, 'j': 0.000, 'k': 0.000, 'l': 0.000, 'm': 0.000,
        'n': 0.000, 'o': 0.000, 'p': 0.000, 'q': 0.000, 'r': 0.000,
        's': 0.000, 't': 0.000, 'u': 0.000, 'v': 0.000, 'w': 0.000,
        'x': 0.000, 'y': 0.000, 'z': 0.000}
    total = 0
    
    with open('letterFrequencies.json') as data_file:    
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
    
if __name__ == "__main__":
    implement_repeating_key_xor("Set1Challenge5InputFile.txt","ICE")