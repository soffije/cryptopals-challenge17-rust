use std::io::{self, Write};

use base64::{Engine as _, engine::general_purpose};
use crypto::aes::{self, KeySize};
use crypto::blockmodes::{NoPadding, PkcsPadding};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use rand::Rng;

#[derive(Debug)]
enum EncryptionError {
    SymmetricCipherError(crypto::symmetriccipher::SymmetricCipherError),  // Wraps a SymmetricCipherError
}

#[derive(Debug)]
enum DecryptionError {
    SymmetricCipherError(crypto::symmetriccipher::SymmetricCipherError), // Wraps a SymmetricCipherError
    PaddingError,  // Indicates an invalid padding error during decryption
}

// To optimize speed performance
static PLAINTEXTS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

// Function to encrypt plaintext
fn encrypt(key: &[u8; 16], iv: &[u8; 16], plaintexts: [&str; 10]) -> Result<(Vec<u8>, String, Vec<u8>), EncryptionError> {
    let mut rng = rand::thread_rng(); // Create a random number generator
    let random_index = rng.gen_range(0..plaintexts.len()); // Generate a random index within the range of the plaintexts array
    let plaintext = general_purpose::STANDARD.decode(plaintexts[random_index]).unwrap(); // Retrieve the plaintext at the randomly selected index
    let encoded_plaintext = general_purpose::STANDARD.encode(&plaintext[..]); // Encode the plaintext using base64 encoding

    let mut encryptor = aes::cbc_encryptor(KeySize::KeySize128, key, iv, PkcsPadding); // Create an AES CBC encryptor with a key, IV, and padding mode
    let mut buffer = [0; 1024]; // Create a buffer to store the encrypted data

    // Create read and write buffers for the encryption process
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(&plaintext);
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

    let mut encrypted_data = Vec::new(); // Create a vector to store the encrypted data

    // Perform the encryption in a loop until all data is processed
    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true); // Attempt to encrypt data from the read buffer to the write buffer

        // Handle the result of the encryption operation
        match result {
            // If the encryption operation finished and there is no more data to encrypt
            Ok(BufferResult::BufferUnderflow) => {
                encrypted_data.extend_from_slice(write_buffer.take_read_buffer().take_remaining()); // Append the remaining data from the write buffer to the encrypted data vector
                break;
            }
            // If the write buffer is full and there is more data to encrypt
            Ok(BufferResult::BufferOverflow) => {
                encrypted_data.extend_from_slice(write_buffer.take_read_buffer().take_remaining()); // Append the encrypted data from the write buffer to the encrypted data vector
            }
            // If an error occurred during encryption
            Err(err) => return Err(EncryptionError::SymmetricCipherError(err)),
        }
    }
    Ok((encrypted_data, encoded_plaintext, plaintext.to_vec())) // Return the encrypted data, encoded plaintext, and original plaintext vector as a result
}

// Function to decrypt ciphertext and check padding, including padding oracle attack
fn decrypt_and_check_padding(ciphertext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<bool, DecryptionError> {
    let mut decryptor = aes::cbc_decryptor(KeySize::KeySize128, key, iv, NoPadding);  // Create an AES decryptor with CBC mode and no padding (for attack)
    let mut buffer = [0; 1024];  // Create a buffer to store the decrypted data
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(ciphertext);  // Create a read buffer for the ciphertext
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);  // Create a write buffer for the decrypted data

    let mut decrypted_data = Vec::with_capacity(ciphertext.len());  // Vector to store the decrypted data

    // Loop to read, decrypt and write data
    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true);  // Decrypt data from the read buffer to the write buffer
        match result {
            Ok(BufferResult::BufferUnderflow) => {  // If all data has been decrypted
                decrypted_data.extend_from_slice(write_buffer.take_read_buffer().take_remaining());  // Append the remaining decrypted data to the result vector
                break;  // Exit the loop
            }
            Ok(BufferResult::BufferOverflow) => {  // If the write buffer is full
                decrypted_data.extend_from_slice(write_buffer.take_read_buffer().take_remaining());  // Append the decrypted data to the result vector
            }
            Err(err) => return Err(DecryptionError::SymmetricCipherError(err)),  // Return a decryption error if an error occurs
        }
    }

    let padding_length = decrypted_data.last().cloned().unwrap_or(0);  // Get the length of the padding

    // Perform padding oracle attack
    let mut modified_ciphertext = ciphertext.to_vec();

    // Iterate over the indices of ciphertext in reverse order, with a step of 16 (block size)
    for i in (0..ciphertext.len()).rev().step_by(16) {
        let mut padding_bytes = Vec::new(); // Create an empty vector to store the padding bytes

        // Iterate over the indices from i to the end of ciphertext in reverse order
        for j in (i..ciphertext.len()).rev() {
            let padding_byte = padding_length ^ (ciphertext[j] ^ (padding_bytes.len() as u8 + 1)); // Calculate the padding byte by XORing padding_length with ciphertext and the length of padding_bytes
            padding_bytes.push(padding_byte); // Append the padding byte to the padding_bytes vector
        }

        // Iterate over all possible byte values (0 to 255) as potential guesses for the padding byte
        for guess in 0..=255 {
            modified_ciphertext[i..].iter_mut().zip(padding_bytes.iter().rev()).for_each(|(c, p)| *c = *p ^ guess); // XOR each byte in the modified ciphertext with the corresponding padding byte guess

            let result = decryptor.decrypt(&mut crypto::buffer::RefReadBuffer::new(&modified_ciphertext), &mut write_buffer, true); // Decrypt the modified ciphertext using the decryptor

            // Check if the decryption resulted in an InvalidPadding error
            if let Err(crypto::symmetriccipher::SymmetricCipherError::InvalidPadding) = result {
                continue; // If there is an InvalidPadding error, continue to the next guess
            }

            let is_padding_valid = if result.is_ok() {
                // Collect the remaining bytes in the write buffer as padding bytes
                let padding_bytes = write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .to_vec();
                padding_bytes.iter().all(|&byte| byte == padding_length) // Check if all the padding bytes are equal to the expected padding length
            } else {
                false // If the decryption was not successful, padding is not valid
            };
            if is_padding_valid {
                return Ok(true); // If the padding is valid, return true
            }
        }
    }
    Err(DecryptionError::PaddingError)  // Return a padding error if the padding oracle attack fails
}

fn main() {
    // Generate the key and IV for the session
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    let iv: [u8; 16] = rng.gen();

    loop {
        // Encrypting the plaintext
        let encryption_result = encrypt(&key, &iv, PLAINTEXTS);
        if let Ok((ciphertext, encoded_plaintext, plaintext)) = encryption_result {
            // Decrypting the ciphertext and checking the padding
            let decryption_result = decrypt_and_check_padding(&ciphertext, &key, &iv);
            match decryption_result {
                Ok(is_padding_valid) => {
                    // Printing the results
                    println!("Encoded Plaintext (Base64): {:?}", encoded_plaintext);
                    println!("Plaintext: {:?}", plaintext.iter().map(|&byte| byte as char).collect::<String>());
                    println!("Ciphertext: {:?}", ciphertext.iter().map(|&byte| format!("{:02X}", byte)).collect::<String>());
                    println!("Key: {:?}", key.iter().map(|&byte| format!("{:02X}", byte)).collect::<String>());
                    println!("IV: {:?}", iv.iter().map(|&byte| format!("{:02X}", byte)).collect::<String>());
                    println!("Is padding valid: {:?}", (is_padding_valid));
                }
                Err(DecryptionError::SymmetricCipherError(err)) => {
                    println!("Decryption error: {:?}", err);
                }
                Err(DecryptionError::PaddingError) => {
                    println!("Invalid padding");
                }
            }
        } else {
            println!("Encryption error");
        }
        // Prompting the user to continue or exit (like a "session")
        print!("\nContinue? (y/n): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();

        if input != "y" {
            break;
        }
    }
}