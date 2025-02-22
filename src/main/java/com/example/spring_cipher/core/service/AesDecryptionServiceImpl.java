package com.example.spring_cipher.core.service;

import com.example.spring_cipher.shell.error.decrypt.AesDecryptionException;
import com.example.spring_cipher.shell.service.AesDecrypionService;
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
import java.util.Arrays;
import java.util.Base64;

import static com.example.spring_cipher.shell.AppConstants.ALGORITHM;
import static com.example.spring_cipher.shell.AppConstants.TRANSFORMATION;

@Service
public class AesDecryptionServiceImpl implements AesDecrypionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AesDecryptionServiceImpl.class);

    private SecretKeySpec secretKeySpec;

    @Value("${aes.key:MySuperSecretKey }")
    private String aesKey;

    @PostConstruct
    public void init() {
        LOGGER.info("Initializing AesDecryptionServiceImpl with provided AES key.");
        byte[] keyBytes = aesKey.getBytes(StandardCharsets.UTF_8);
        this.secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
    }

    @Override
    public String decrypt(String encryptedText) throws AesDecryptionException {
        LOGGER.info("Starting decryption process.");
        validateInput(encryptedText);

        try {
            byte[] cipherTextWithIv = decodeEncryptedText(encryptedText);
            byte[] iv = extractIV(cipherTextWithIv);
            byte[] cipherText = extractCipherText(cipherTextWithIv);
            Cipher cipher = createInitializedCipher(iv);
            byte[] plainBytes = performDecryption(cipher, cipherText);
            String result = new String(plainBytes, StandardCharsets.UTF_8);
            LOGGER.info("Decryption process completed successfully.");
            return result;
        } catch (GeneralSecurityException e) {
            LOGGER.error("Error during AES decryption", e);
            throw new AesDecryptionException("Decryption failed", e);
        }
    }

    private void validateInput(String encryptedText) throws AesDecryptionException {
        if (encryptedText == null || encryptedText.isEmpty()) {
            LOGGER.error("Encrypted text validation failed: input is null or empty.");
            throw new AesDecryptionException("Encrypted text must not be null or empty");
        }
    }

    // Decodes the Base64-encoded string to bytes
    private byte[] decodeEncryptedText(String encryptedText) {
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        LOGGER.info("Decoded encrypted text from Base64. Byte length: {}.", decoded.length);
        return decoded;
    }

    // Extracts the IV from the first 12 bytes of the decoded array
    private byte[] extractIV(byte[] cipherTextWithIv) {
        byte[] iv = Arrays.copyOfRange(cipherTextWithIv, 0, 12);
        LOGGER.info("Extracted IV from decoded data: {}.", Base64.getEncoder().encodeToString(iv));
        return iv;
    }

    // Extracts the actual ciphertext after the IV
    private byte[] extractCipherText(byte[] cipherTextWithIv) {
        byte[] cipherText = Arrays.copyOfRange(cipherTextWithIv, 12, cipherTextWithIv.length);
        LOGGER.info("Extracted ciphertext from decoded data. Ciphertext byte length: {}.", cipherText.length);
        return cipherText;
    }

    // Initializes the cipher in decryption mode with the given IV
    private Cipher createInitializedCipher(byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec);
        LOGGER.info("Cipher initialized for decryption with IV.");
        return cipher;
    }

    // Performs the actual decryption process
    private byte[] performDecryption(Cipher cipher, byte[] cipherText) throws GeneralSecurityException {
        byte[] plainBytes = cipher.doFinal(cipherText);
        LOGGER.info("Data decrypted successfully. Plaintext byte length: {}.", plainBytes.length);
        return plainBytes;
    }
}
