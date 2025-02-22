package com.example.spring_cipher;

import com.example.spring_cipher.core.service.RsaEncryptionServiceImpl;
import com.example.spring_cipher.shell.dto.RsaEncryptedPayload;
import com.example.spring_cipher.shell.error.encrypt.RsaEncryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class RsaEncryptionServiceTest {

    private RsaEncryptionServiceImpl encryptionService;
    private String base64PrivateKey;

    @BeforeEach
    void setUp() throws Exception {
        // GIVEN: a generated RSA key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        base64PrivateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        // GIVEN: an instance of the encryption service with injected private key
        encryptionService = new RsaEncryptionServiceImpl();
        ReflectionTestUtils.setField(encryptionService, "rsaPrivateKey", base64PrivateKey);
        encryptionService.init();
    }

    @Test
    void testEncryptionSuccess() {
        // GIVEN: a valid plain text input
        String originalText = "Hello, RSA Option2!";

        // WHEN: encrypting the plain text
        RsaEncryptedPayload payload = encryptionService.encrypt(originalText);

        // THEN: a non-null payload is returned with both encrypted data and a signature
        assertNotNull(payload, "Payload should not be null");
        assertNotNull(payload.getEncryptedData(), "Encrypted data should not be null");
        assertNotNull(payload.getSignature(), "Signature should not be null");
    }

    @Test
    void testEncryptionFailsWithEmptyPlainText() {
        // GIVEN: an empty plain text input
        String emptyText = "";

        // WHEN / THEN: encryption should throw an exception
        assertThrows(RsaEncryptionException.class, () -> encryptionService.encrypt(emptyText),
                "Encryption should fail with empty plain text");
    }
}
