# The CBC padding oracle

This code is an implementation of an oracle attack on the AES block cipher in CBC (Cipher Block Chaining) mode. Let's take a closer look at it:

1. The `encrypt` function takes a key, initializing vector (iv) and an array of plaintexts as input parameters and returns the encrypted data, the encoded source text and the original text as Result<(Vec<u8>, String, Vec<u8>)> or EncryptionError. The function performs symmetric AES encryption in CBC mode with PKCS7 paddings added.

2. The `decrypt_and_check_padding` function takes the encrypted data (ciphertext), key (key) and initializing vector (iv) as input parameters and returns Result<bool> indicating whether padding is valid or not or DecryptionError. This function is used to decrypt data and verify the validity of padding with a padding oracle attack. It is important to note that no padding is used here during the decryption (it works in NoPadding mode) just because of the attack demonstration.

3. And the main `main` function generates a key and an initializing vector, and then runs a loop to encrypt and decrypt the messages. It works as a demonstration of the user session: prOn each iteration of the loop, a randomly chosen message from the PLAINTEXTS array is encrypted, and then a decryption and padding attack is attempted. The results of the encryption, decryption, and verification are displayed on the screen.

Now let's look at how the code performs a padding oracle attack:

In this code, the padding oracle attack is performed inside a loop that iterates through the data block indexes in reverse order, starting from the last block and ending with the first. This is because in CBC data encryption, each data block depends on the previous encrypted block, and changing the last data block affects the validity of padding in that block.

The padded-oracle attack algorithm involves the following steps:

1. Creating a vector `modified_ciphertext` which is a copy of the original encrypted text (`ciphertext`). This is necessary to modify the blocks and check the validity of the paddings.

2. Iterating over the data blocks indexes in reverse order, with steps equal to the block size (16 bytes). This allows us to modify each block from the end to the beginning, starting from the last block.

3. Within each iteration, the following happens:
   - Creation of a vector `padding_bytes` to store the padding bytes. The padding bytes obtained during the padding validity check will be added to it.
   - Iterate through the indices from the current index `i` to the end of the vector `ciphertext` in reverse order. This allows us to change each byte of the block from the end to the beginning, starting from the last byte.
   - Calculation of `padding_byte` bytes by applying XOR operations on `padding_length` (padding length), byte of original ciphertext and length of `padding_bytes`. This is necessary to get the correct padding byte, which will result in a valid padding.
   - Adding `padding_byte` to the `padding_bytes` vector. This saves all the bytes of the padding received during the validation of the padding.
   - Changing the last byte of the block of the vector `modified_ciphertext` by applying XOR operation on the current byte and `padding_byte`. This change allows us to create a modified block, which will be checked for padding validity.
   - Decrypt the modified vector `modified_ciphertext` using the function `decryptor.decrypt`. This is necessary to check the validity of the paddings after modification.
   - Checking the decrypt result for an `InvalidPadding` error. If no error occurs, then the validity of the padding is checked by comparing all bytes of the padding with the expected length `padding_length`. If all bytes of the padding match the expected length, the padding is considered valid and the function returns `true`.
   - If the `InvalidPadding` error does not occur and the padding is not valid, the algorithm proceeds to the next iteration of the loop, where the previous byte is changed.

The goal of the padding oracle attack is to use the information about the validity of the padding to sequentially reconstruct the byte values of the last data block. It is assumed that the length of the padding is known to the attacker.

The attack works on the principle of going through possible padding byte values and checking the validity of the padding after each modification. If the paddding is valid, it means that the previous byte has a value that makes the paddding correct. By sequentially modifying bytes and analyzing the validity of the paddings, you can recover the byte values of the last data block.

If the padding oracle attack is performed correctly, after iterating over all possible padding byte values for each data block, all byte values of the last block will be restored. This is because each iteration provides information about the value of the previous byte.



