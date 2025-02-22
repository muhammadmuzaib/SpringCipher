package com.example.spring_cipher.core.service;

import com.example.spring_cipher.shell.dto.RsaEncryptedPayload;
import com.example.spring_cipher.shell.error.decrypt.RsaDecryptionException;
import com.example.spring_cipher.shell.service.RsaDecryptionService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class RsaDecryptionServiceImpl implements RsaDecryptionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RsaDecryptionServiceImpl.class);
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    @Value("${rsa.public.key}")
    private String rsaPublicKey;

    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        LOGGER.info("RSA Public Key: '{}'", rsaPublicKey);
        LOGGER.info("Initializing RsaDecryptionServiceOption2Impl with the provided RSA public key.");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(rsaPublicKey.trim());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            LOGGER.error("Error initializing RSA public key", e);
            throw new RuntimeException("Failed to initialize RSA public key", e);
        }
    }

    @Override
    public String decrypt(RsaEncryptedPayload payload) throws RsaDecryptionException {
        LOGGER.info("Starting RSA Option2 decryption process.");
        validatePayload(payload);
        try {
            byte[] encryptedBytes = decodeBase64(payload.getEncryptedData());
            Cipher cipher = initializeCipherForDecryption();
            byte[] decryptedBytes = decryptData(encryptedBytes, cipher);
            String plainText = new String(decryptedBytes, StandardCharsets.UTF_8);

            byte[] signatureBytes = decodeBase64(payload.getSignature());
            if (!verifySignature(plainText, signatureBytes)) {
                LOGGER.error("Signature validation failed.");
                throw new RsaDecryptionException("Signature validation failed");
            }
            LOGGER.info("RSA Option2 decryption and signature validation completed successfully.");
            return plainText;
        } catch (Exception e) {
            LOGGER.error("Error during RSA Option2 decryption", e);
            throw new RsaDecryptionException("RSA Option2 decryption failed", e);
        }
    }

    private void validatePayload(RsaEncryptedPayload payload) throws RsaDecryptionException {
        if (payload == null ||
                payload.getEncryptedData() == null || payload.getEncryptedData().isEmpty() ||
                payload.getSignature() == null || payload.getSignature().isEmpty()) {
            LOGGER.error("Payload validation failed: Encrypted data or signature is missing.");
            throw new RsaDecryptionException("Payload must contain both encrypted data and signature");
        }
    }

    private Cipher initializeCipherForDecryption() throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        LOGGER.info("Cipher initialized for RSA Option2 decryption using transformation: {}", RSA_TRANSFORMATION);
        return cipher;
    }

    private byte[] decryptData(byte[] encryptedBytes, Cipher cipher) throws Exception {
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        LOGGER.info("Data decrypted using public key. Decrypted byte length: {}", decryptedBytes.length);
        return decryptedBytes;
    }

    // Decode Base64-encoded string
    private byte[] decodeBase64(String encodedText) {
        byte[] decoded = Base64.getDecoder().decode(encodedText);
        LOGGER.info("Decoded Base64 text. Byte length: {}", decoded.length);
        return decoded;
    }

    // Verify the digital signature using the public key
    private boolean verifySignature(String plainText, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        boolean isValid = signature.verify(signatureBytes);
        LOGGER.info("Signature verification result: {}", isValid);
        return isValid;
    }
}
