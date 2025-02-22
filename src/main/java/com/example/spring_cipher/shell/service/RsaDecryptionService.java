package com.example.spring_cipher.shell.service;

import com.example.spring_cipher.shell.dto.RsaEncryptedPayload;
import com.example.spring_cipher.shell.error.decrypt.RsaDecryptionException;

public interface RsaDecryptionService {

    /**
     * Decrypts the payload using the public key and verifies its signature.
     * Returns the original plain text if the signature is valid.
     */
    String decrypt(RsaEncryptedPayload payload) throws RsaDecryptionException;
}
