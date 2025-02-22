package com.example.spring_cipher.core.service;

import com.example.spring_cipher.shell.dto.RsaEncryptedPayload;
import com.example.spring_cipher.shell.error.encrypt.RsaEncryptionException;
import com.example.spring_cipher.shell.service.RsaEncryptionService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Service
public class RsaEncryptionServiceImpl implements RsaEncryptionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RsaEncryptionServiceImpl.class);
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    @Value("${rsa.private.key}")
    private String rsaPrivateKey;

    private PrivateKey privateKey;

    @PostConstruct
    public void init() {
        LOGGER.info("RSA Private Key: '{}'", rsaPrivateKey);
        LOGGER.info("Initializing RsaEncryptionServiceImpl with the provided RSA private key.");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(rsaPrivateKey.trim());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            LOGGER.error("Error initializing RSA private key", e);
            throw new RuntimeException("Failed to initialize RSA private key", e);
        }
    }

    @Override
    public RsaEncryptedPayload encrypt(String plainText) throws RsaEncryptionException {
        LOGGER.info("Starting RSA encryption (private-key encryption/signing) process.");
        validatePlainText(plainText);
        try {
            Cipher cipher = initializeCipherForEncryption();
            byte[] encryptedBytes = encryptData(plainText, cipher);
            String encryptedData = encodeBase64(encryptedBytes);

            byte[] signatureBytes = generateSignature(plainText);
            String signature = encodeBase64(signatureBytes);

            LOGGER.info("RSA Option2 encryption process completed successfully.");
            return new RsaEncryptedPayload(encryptedData, signature);
        } catch (Exception e) {
            LOGGER.error("Error during RSA Option2 encryption", e);
            throw new RsaEncryptionException("RSA Option2 encryption failed", e);
        }
    }

    // Helper: Validate input
    private void validatePlainText(String plainText) throws RsaEncryptionException {
        if (plainText == null || plainText.isEmpty()) {
            LOGGER.error("Plain text validation failed: input is null or empty.");
            throw new RsaEncryptionException("Input plain text must not be null or empty");
        }
    }

    // Helper: Initialize Cipher for encryption using the private key
    private Cipher initializeCipherForEncryption() throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        LOGGER.info("Cipher initialized for RSA Option2 encryption using transformation: {}", RSA_TRANSFORMATION);
        return cipher;
    }

    // Helper: Encrypt data (using private key encryption)
    private byte[] encryptData(String plainText, Cipher cipher) throws Exception {
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(plainBytes);
        LOGGER.info("Data encrypted using private key. Encrypted byte length: {}", encryptedBytes.length);
        return encryptedBytes;
    }

    // Helper: Generate a digital signature for the plain text
    private byte[] generateSignature(String plainText) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        LOGGER.info("Generated signature for plain text. Signature byte length: {}", signatureBytes.length);
        return signatureBytes;
    }

    // Helper: Encode bytes to Base64 string
    private String encodeBase64(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        LOGGER.info("Encoded data to Base64.");
        return encoded;
    }
}
