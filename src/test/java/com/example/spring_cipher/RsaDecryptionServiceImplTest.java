package com.example.spring_cipher;

import com.example.spring_cipher.core.service.RsaDecryptionServiceImpl;
import com.example.spring_cipher.core.service.RsaEncryptionServiceImpl;
import com.example.spring_cipher.shell.dto.RsaEncryptedPayload;
import com.example.spring_cipher.shell.error.decrypt.RsaDecryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RsaDecryptionServiceImplTest {

    private RsaDecryptionServiceImpl decryptionService;
    private RsaEncryptionServiceImpl encryptionService;
    private String privateKey;
    private String publicKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Given
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        var keyPair = keyGen.generateKeyPair();
        privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // Given
        decryptionService = new RsaDecryptionServiceImpl();
        ReflectionTestUtils.setField(decryptionService, "rsaPublicKey", publicKey);
        decryptionService.init();

        // Given
        encryptionService = new RsaEncryptionServiceImpl();
        ReflectionTestUtils.setField(encryptionService, "rsaPrivateKey", privateKey);
        encryptionService.init();
    }

    @Test
    void GivenValidPlainTextAndPayloadThenTestDecryptionSuccess() {
        // Given
        String originalText = "Hello, RSA Option2!";
        RsaEncryptedPayload payload = encryptionService.encrypt(originalText);

        // When
        String decryptedText = decryptionService.decrypt(payload);

        // Then
        assertEquals(originalText, decryptedText, "Decrypted text should match the original");
    }

    @Test
    void GivenValidPayloadAndTextThenTestDecryptionFailsWithTamperedSignature() {
        // Given
        String originalText = "Test message";
        RsaEncryptedPayload payload = encryptionService.encrypt(originalText);

        // When
        String badSignature = payload.getSignature().substring(0, payload.getSignature().length() - 1) + "A";
        RsaEncryptedPayload badPayload = new RsaEncryptedPayload(payload.getEncryptedData(), badSignature);

        // Then
        assertThrows(RsaDecryptionException.class, () -> decryptionService.decrypt(badPayload),
                "Decryption should fail if the signature is tampered");
    }

    @Test
    void GivenEmptyPayloadThenThrowsRsaDecryptionException() {
        // Given
        RsaEncryptedPayload emptyPayload = new RsaEncryptedPayload("", "");

        // Then
        assertThrows(RsaDecryptionException.class, () -> decryptionService.decrypt(emptyPayload),
                "Decryption should fail with an empty payload");
    }
}
