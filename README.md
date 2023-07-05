# The CBC padding oracle

This code is an implementation of an oracle attack on the AES block cipher in CBC (Cipher Block Chaining) mode. Let's take a closer look at it:

The code defines three main functions: `encrypt`, `decrypt_and_check_padding` and `main`.

1. The `encrypt` function takes a key, an initialization vector (iv), and a plaintext array as input parameters. It performs symmetric AES encryption in CBC mode with PKCS7 extension. It randomly selects a plaintext from the array, encodes it using base64, encrypts it using AES CBC encryption with the provided key and iv, and returns the encrypted data, the encoded plaintext, and the original plaintext as a tuple.

2. The `decrypt_and_check_padding` function takes the encrypted data (ciphertext), the key and the initialization vector as input parameters. It decrypts the ciphertext using AES CBC decryption without padding (for the purpose of a padded oracle attack). It then verifies the validity of the complement using a complement oracle attack. If the complement is valid, it returns `Ok(true)`, indicating that the complement was successfully verified. If the complement is invalid or the decryption process encountered an error, the corresponding `DecryptionError` is returned.

3. The `main` function is the entry point to the program. It generates a key and an initialization vector for the session using the `SessionData` structure, which is created for convenient "memorization" of parameters for encryption sessions so that they are the same according to the task (this is also done to prevent hardcoding in the main function, it does not affect the efficiency, but it is really more beautiful :) ). It enters a loop that encrypts and decrypts the message using the generated key and iv. At each iteration, a random plaintext is selected from the `PLAINTEXTS` array, encrypted, and then decrypted with a space check. The results of encryption, decryption, and hyphenation are displayed on the screen. After each iteration, the user is prompted to continue or exit the cycle.

The code also defines several types of errors (`EncryptionError` and `DecryptionError`) to handle encryption and decryption errors.

In general, this code demonstrates the process of encrypting and decrypting messages using AES CBC encryption with PKCS7 substitution and demonstrates a vulnerability to substitution during the decryption process.

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
