import unittest
from setonechallenges import *

class TestMethods(unittest.TestCase):
    
#    Set 1, Challenge 1
    def test_hex(self):
        self.assertEqual(set_one_challenge_one('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
        'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
        
#    Set 1, Challenge 2        
    def test_xor(self):
        self.assertEqual(set_one_challenge_two('1c0111001f010100061a024b53535009181c','686974207468652062756c6c277320657965'),'746865206b696420646f6e277420706c6179') 
          
#    Set 1, Challenge 3
    def test_decode_xor(self):
        self.assertEqual(set_one_challenge_three('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'), "Cooking MC's like a pound of bacon")

#    Set 1, Challenge 4
    def test_detect_single_xor(self):
        self.assertEqual(set_one_challenge_four("TestInputFiles/Set1Challenge4SuppliedFile.txt")[0], "Now that the party is jumping\n")
  
#    Set 1, Challenge 5
    def test_implement_repeating_key_xor(self):
        self.assertEqual(set_one_challenge_five("TestInputFiles/Set1Challenge5SuppliedFile.txt","ICE"),"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    
#    Set 1, Challenge 6    
    def test_break_repeating_key_xor(self):
        self.assertEqual(set_one_challenge_six("TestInputFiles/Set1Challenge6SuppliedFile.txt"),read_file("TestAnswerFiles/Set1Challenge6Answer.txt"))
        
#    Set 1, Challenge 7
    def test_unencrypt_AES128ECB(self):
        self.assertEqual(set_one_challenge_seven("TestInputFiles/Set1Challenge7SuppliedFile.txt","YELLOW SUBMARINE"),read_file("TestAnswerFiles/Set1Challenge7Answer.txt"))
   
#    Set 1, Challenge 8
    def test_detect_aesinecb(self):
        self.assertEqual(set_one_challenge_eight("TestInputFiles/Set1Challenge8SuppliedFile.txt")[0],132)

if __name__ == "__main__":
    unittest.main()