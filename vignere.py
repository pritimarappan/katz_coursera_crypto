from __future__ import division
import binascii
from itertools import izip, cycle

#Key length is between 1 to 13

# For a given key length, pick all the bytes of ciphertext that were encrypted with the same key byte and form set 's'. For ex., if key length is 4, every 4th byte of the ciphertext would be encrypted with the same key byte

# For every char in s, calculate  frequency qi in set s (is this the number of times the byte is repeated in the set s divided by length of that set)

# Calculate summation of qi*qi. key_length corresponds to the value used to get maximum value of  qi * qi

# Since it is known that plaintext consists only of valid english text characters, xor chiphertext with each possible key value and select valid plaintext.

#  ***** quotation marks (") is a valid english character, but is not considered as one here to make the program cleaner.

def get_char_set(key_length, input_string, start_index):
    char_set = input_string[start_index::key_length]
    return char_set

def get_frequency_sq(byte_set):
    frequency_sq = 0.0
    hex_set = binascii.hexlify(byte_set)
    set_length = len(byte_set)
    for i in range(0, len(hex_set), 2):
        freq = hex_set.count(hex_set[i:i+2])
        frequency_sq += (freq/set_length) ** 2
    return frequency_sq

def all_bytes_in_valid_range(byte_set):
    #print "\n", byte_set 
    valid_char_set = [32, 33, 38, 39, 40, 41, 44, 45, 46, 63] #65-90 , 97-122
    if(all(((i>= 65 and i <= 90) or (i>= 97 and i <= 122) or (i>= 48 and i <= 59)  or i in valid_char_set)  for i in byte_set)):
        return True
    return False

def main():
    ciphertext = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"
    ciphertext_in_bytes = bytearray.fromhex(ciphertext)
    key_length = 0
    qi2 = 0.0

    for key_len in range (1,14):
        computed_freq = get_frequency_sq(get_char_set(key_len, ciphertext_in_bytes, 0))
        if computed_freq > qi2:
            qi2 = computed_freq
            key_length = key_len
    #print("key length: %d" %key_length)

    #iterate through all possible values for each  byte of the key
    key = [0]*key_length
    valid_key_candidate = {}

    for key_index in range(0,7):
        #valid_key_candidate = []
        byte_set = get_char_set(key_length, ciphertext_in_bytes,key_index)
        for i in range(0,256):
            s = bytearray(i ^ x for x in byte_set)
            if(all_bytes_in_valid_range(s)):
                    #print "\n candidate key: ", i
                    #print "\n", s
                    key[key_index] = i
   
    #print key, "\n"
        
    #key = [186, 31, 145, 178, 83, 205, 62]
    plaintext_in_bytes = ''.join(chr(c ^ k) for c, k in izip(ciphertext_in_bytes, cycle(key)))
    #print "plain_text"
    print plaintext_in_bytes

if __name__ == "__main__": main()
        
