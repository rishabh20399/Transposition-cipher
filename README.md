# Transposition-cipher
Encryption &amp; decryption using transposition of the kind discussed in class. Then develop the software to launch a brute-force attack to discover the key. Here assume that the key length is known to be 9 or less.

In our code, we have HARD-CODED the plaintext values.
(However, the code has been tested for multiple test cases, and the code can be changed very easily to take user input)
Similarly, the key has also been hard-coded. (and it can also be taken as user input, or generated randomly)

Input:
The 2 inputs are the set of plaintexts and the key.
1) Set of Plaintexts: ['attackpostponeduntiltwoam', 'transpositionencryptiondecryption', 'wehavecodedtranspostion', 'saviourofalhumanity', 				'securityisjustamyth']
2) The chosen key is: "4312567"

Output:

On running the program, hash values, modified plaintexts, and encrypted ciphertexts are generated.
However, the output of interest to the brute-force attacker is the set of possible keys. For the given input, 
the output that we get is: "4312567", which is the same as the selected key.
Thus, by doing a brute-force attack, the attacker obtains the required key.
