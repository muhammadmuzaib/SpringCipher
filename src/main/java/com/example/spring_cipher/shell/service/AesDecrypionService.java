package com.example.spring_cipher.shell.service;

import com.example.spring_cipher.shell.error.decrypt.AesDecryptionException;

public interface AesDecrypionService {

    /**
     * Decrypts the given Base64-encoded cipher text.
     *
     * @param encryptedText the cipher text to decrypt.
     * @return the decrypted plain text.
     * @throws AesDecryptionException if decryption fails or the input is invalid.
     */
    String decrypt(String encryptedText) throws AesDecryptionException;
}
