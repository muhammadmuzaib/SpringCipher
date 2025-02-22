package com.example.spring_cipher.shell.service;

import com.example.spring_cipher.shell.error.encrypt.AesEncryptionException;

public interface AesEncryptionService {

    /**
     * Encrypts the provided plain text using AES encryption.
     *
     * @param plainText the text to encrypt
     * @return the encrypted text in Base64 format
     * @throws AesEncryptionException if encryption fails
     */
    String encrypt(String plainText) throws AesEncryptionException;
}
