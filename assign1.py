#this is imported to use permutaion function
from itertools import *

def hash_function(word):
    #this function is an extension of Polynomial hashing function from GFG

    #length of word is calculated using len()
    length = len(word)
    #this value will store the sum of weight*(47^(position of that character))
    total_val = 0
    #prime number 47 by us (GFG suggested 31 for [a-z] 
    #but it also said the bigger the number the better it is)
    prime_number = 47

    #each character in the plaintext is iterated over
    #then they are mapped to number 1-26 and then,
    #weight * (prime_number ** i)
    for i in range(length):
        weight = ord(word[i]) - 96
        total_val += weight*(prime_number ** i)

    #converting decimal to binary
    bin_string = bin(total_val)[2:]
    #length of binary number is calculated
    length2 = len(bin_string)

    #if length2 is <35 then add '0' required number of time to make the legth of binary number 35
    #else take last 35 bits in result variable
    #this variable is then used to make 7 groups which will ultimately form Hash value
    if length2 < 35:
        diff = 35 - length2
        result = '0' * diff + bin_string
    else:
        result = bin_string[-35:]

    #7 groups are made each contains of 5 bits and also a map is made which will help in creating hash_value
    group1, group2, group3, group4, group5, group6, group7 = result[0:5], result[5:10], result[10:15], result[15:20], result[20:25], result[25:30], result[30:]
    #mapping of binary groups to characters
    map_char = {"00000":'a', "00001":'b', "00010":'c', "00011":'d', "00100":'e', "00101":'f',
                "00110":'g', "00111":'h', "01000":'i', "01001":'j', "01010":'k', "01011":'l', "01100":'m',
                "01101":'n', "01110":'o', "01111":'p', "10000":'q', "10001":'r', "10010":'s', "10011":'t',
                "10100":'u', "10101":'v', "10110":'w', "10111":'x', "11000":'y', "11001":'z', "11010":'a',
                "11011":'b', "11100":'c', "11101":'d', "11110":'e', "11111":'f'}
    #final hash value using map_char
    hash_value = map_char[group1] + map_char[group2] + map_char[group3] + map_char[group4] + map_char[group5] + map_char[group6] + map_char[group7]
    #returning hash value
    return hash_value


def transposition_encrypt(plaintext, key):
    #a list of column order like [0,1,2 .... key_length-1]
    #list is then sorted based on corresponding digit in the key using lambda functiom
    order = list(range(len(key)))
    order.sort(key=lambda x: key[x])

    #number of rows and is calculayted
    cols = len(key)
    rows = (len(plaintext) + cols - 1) // cols
    #the number of hyphens to be added so during decryption it don't create error
    num_hyphens = rows * cols - len(plaintext)
    #adding hyphens to the plaintext
    plaintext += '-' * num_hyphens

    #an empty string is created
    ciphertext = ""
    #iterate over columns in specific order and then inside this iterate over rows in blocks
    #of key-length to do transposition encryption
    for col in order:
        for row in range(0, len(plaintext), cols):
            index = row + col
            if index < len(plaintext):
                #in ciphertext, character at calculated index is appended to make encrypted text
                ciphertext += plaintext[index]
    #returning encrypted text
    return ciphertext


def transposition_decrypt(ciphertext, key):
    #a list of column order like [0,1,2 .... key_length-1]
    #list is then sorted based on corresponding digit in the key using lambda functiom
    order = list(range(len(key)))
    order.sort(key=lambda x: key[x])
    #number of rows and cols is calculayted
    cols = len(key)
    rows = (len(ciphertext) + cols - 1) // cols
    #emppty string matrix to store the characters is created
    matrix = [[''] * cols for _ in range(rows)]
    # Fill in the matrix with the ciphertext
    index = 0
    #iterate over col and then inside this iterate over row in blocks in
    #specified order to do transposition decryption
    for col in order:
        for row in range(rows):
            if index < len(ciphertext):
                matrix[row][col] = ciphertext[index]
                index += 1
            else:
                break
    #plaintext from matrix is created
    plaintext = ""
    for row in range(rows):
        plaintext += ''.join(matrix[row])
    #returning plaintext without hyphens which we added during encryption
    return plaintext.rstrip('-')


def brute_force_attack(ciphertexts, possible_keys):
    #iterate through each possible transposition key
    for current_key in possible_keys:
        #for each key do this
        count = 0
        #making list of deciphered_texts which contains decrypted plaintexts
        #for each ciphertext for current key using Tranposition decrypt
        deciphered_texts = []
        for text in ciphertexts:
            plaintext = transposition_decrypt(text, current_key)
            deciphered_texts.append(plaintext)
        #This is property checker for us
        #here it will check if hash(plaintext[:-7]) == plaintext[-7:]
        #if satisfied which means current key is working for ciphertext and we increement count by 1
        for decrypted_text in deciphered_texts:
            #original plaintext is extracted excluding hashed value
            org = decrypted_text[:-7]
            # print(decrypted_text[-7:])
            # print(hash_function(org))
            #property is being checked
            if hash_function(org) == decrypted_text[-7:]:
                count += 1
            else:
                break  #breaking the loop if plaintext fails the property

        #if all the ciphertexts in the list satisfy the property
            #this means current key is the key and we will return the key
        if count == len(ciphertexts):
            return current_key
    #if no key found return none
    return None


def generate_possible_keylist(max_key_length):
    #to store all possible transposition keys
    all_keys = []
    #iterating through all possible key length and storing different permutation corresponding to all key length
    for length in range(1, max_key_length):
        #list of numbers from 1 to current length
        numbers = list(range(1, length + 1))
        #all permutations of the numbers is generated using permutations function from itertools
        #and these permutations are then added to all_keys list after converting them to string
        for perm in permutations(numbers):
            key = str(''.join(map(str, perm)))
            all_keys.append(key)
    #returning all keys list
    return all_keys


if __name__ == "__main__":
    ############################################################################
    #These are the inputs that we will give to run the code for the Assignment-1
    #This is the original text which we are using for this assignments
    original_texts = [
        "attackpostponeduntiltwoam",
        "transpositionencryptiondecryption",
        "wehavecodedtranspostion",
        "saviourofalhumanity",
        "securityisjustamyth",
    ]
    modified_plaintexts = []
    hashed_list = []
    cipher_texts = []

    #Here we will use the hash-function on each original_text in the list
    #Then the hashed value will be stored in "hashed_list"
    #and original_text||hashed_value will be stored in "modified_plaintexts"
    for text in original_texts:
        hashed_text = hash_function(text)
        hashed_list.append(hashed_text)
        modified_plaintexts.append(text + hashed_text)


    #The transposition key which will use for encryption and decryption
    #and we will try to find this key in brute-force attack
    transposition_key = "4312567"

    #Transposition encrypt will be used here for each modified_plaintext,
    #and ciphertext will be stored in this list
    for text in modified_plaintexts:
        ciphertext = transposition_encrypt(text, transposition_key)
        cipher_texts.append(ciphertext)

    #This list will contain all the permutations of possible keys for key-length in between 1-9
    list_of_possible_keys = generate_possible_keylist(10)

    #We will perform brute-force attack on the list of ciphered_text to find the Transposition key
    brute_force_key = brute_force_attack(cipher_texts, list_of_possible_keys)

    #Printing all the Inputs-Outputs
    print("The list of original plaintexts is: ", original_texts)
    print("The list of hashed values of original texts is: ", hashed_list)
    print("The list of modified plaintexts(org||hash(org)) is: ", modified_plaintexts)
    print("The Key we are using for Transposition is: ", transposition_key)
    print("The list of Ciphertexts are: ", cipher_texts)
    print("The Key returned by Brute_force attack is: ", brute_force_key)  # this should be same as transposition_key