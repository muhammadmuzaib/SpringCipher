package com.example.spring_cipher.shell.service;

import com.example.spring_cipher.shell.dto.RsaEncryptedPayload;
import com.example.spring_cipher.shell.error.encrypt.RsaEncryptionException;

public interface RsaEncryptionService {

    /**
     * Encrypts (signs) the plain text using the private key.
     * Returns a payload that includes the "encrypted" (signed) data and its signature.
     */
    RsaEncryptedPayload encrypt(String plainText) throws RsaEncryptionException;
}
