package com.example.spring_cipher.core.service;

import com.example.spring_cipher.shell.error.encrypt.AesEncryptionException;
import com.example.spring_cipher.shell.service.AesEncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import static com.example.spring_cipher.shell.AppConstants.ALGORITHM;
import static com.example.spring_cipher.shell.AppConstants.TRANSFORMATION;

@Service
public class AesEncryptionServiceImpl implements AesEncryptionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AesEncryptionServiceImpl.class);

    private SecretKeySpec secretKeySpec;

    @Value("${aes.key:MySuperSecretKey }")
    private String aesKey;

    @PostConstruct
    public void init() {
        LOGGER.info("Initializing AesEncryptionServiceImpl with provided AES key.");
        byte[] keyBytes = aesKey.getBytes(StandardCharsets.UTF_8);
        this.secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
    }

    @Override
    public String encrypt(String plainText) throws AesEncryptionException {
        LOGGER.info("Starting encryption process.");
        validatePlainText(plainText);

        try {
            byte[] iv = generateIV();
            Cipher cipher = initializeCipherForEncryption(iv);
            byte[] encryptedBytes = encryptData(plainText, cipher);
            byte[] cipherTextWithIv = combineIvAndCipherText(iv, encryptedBytes);
            LOGGER.info("Encryption process completed successfully.");
            return encodeBase64(cipherTextWithIv);
        } catch (GeneralSecurityException e) {
            LOGGER.error("Error during AES encryption", e);
            throw new AesEncryptionException("Encryption failed", e);
        }
    }

    // Validates the input plain text
    private void validatePlainText(String plainText) throws AesEncryptionException {
        if (plainText == null || plainText.isEmpty()) {
            LOGGER.error("Plain text validation failed: input is null or empty.");
            throw new AesEncryptionException("Input plain text must not be null or empty");
        }
    }

    // Generates a random 12-byte IV for GCM mode
    private byte[] generateIV() {
        byte[] iv = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        LOGGER.info("Generated random IV: {}.", Base64.getEncoder().encodeToString(iv));
        return iv;
    }

    // Initializes the cipher for encryption using the provided IV
    private Cipher initializeCipherForEncryption(byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);
        LOGGER.info("Cipher initialized for encryption with IV.");
        return cipher;
    }

    // Encrypts the plain text using the initialized cipher
    private byte[] encryptData(String plainText, Cipher cipher) throws GeneralSecurityException {
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        LOGGER.info("Data encrypted successfully. Encrypted byte length: {}.", encryptedBytes.length);
        return encryptedBytes;
    }

    // Combines the IV and the encrypted bytes into a single array
    private byte[] combineIvAndCipherText(byte[] iv, byte[] encryptedBytes) {
        byte[] cipherTextWithIv = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, cipherTextWithIv, iv.length, encryptedBytes.length);
        LOGGER.info("IV and ciphertext combined. Total byte length: {}.", cipherTextWithIv.length);
        return cipherTextWithIv;
    }

    // Encodes the final byte array to a Base64 string
    private String encodeBase64(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        LOGGER.debug("Encoded combined data to Base64.");
        return encoded;
    }
}
