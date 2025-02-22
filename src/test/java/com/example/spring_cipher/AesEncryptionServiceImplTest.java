package com.example.spring_cipher;

import com.example.spring_cipher.core.service.AesEncryptionServiceImpl;
import com.example.spring_cipher.shell.error.encrypt.AesEncryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class AesEncryptionServiceImplTest {

    private AesEncryptionServiceImpl aesEncryptionServiceImpl;

    @BeforeEach
    void setUp() {
        aesEncryptionServiceImpl = new AesEncryptionServiceImpl();
        // Given
        ReflectionTestUtils.setField(aesEncryptionServiceImpl, "aesKey", "MySuperSecretKey");
        aesEncryptionServiceImpl.init();
    }

    @Test
    void givenValidPlainTextWhenEncryptThenReturnsEncryptedBase64() {
        // Given
        String plainText = "HelloWorld";

        // When
        String encrypted = aesEncryptionServiceImpl.encrypt(plainText);

        // Then
        assertNotNull(encrypted, "Encrypted text should not be null");
        assertFalse(encrypted.isEmpty(), "Encrypted text should not be empty");
    }

    @Test
    void givenNullPlainTextWhenEncryptThenThrowException() {
        // Given
        String plainText = null;

        // Then
        assertThrows(AesEncryptionException.class, () -> aesEncryptionServiceImpl.encrypt(plainText));
    }

    @Test
    void givenEmptyPlainText_whenEncrypt_thenThrowsAesEncryptionException() {
        // Given
        String plainText = "";

        // Then
        assertThrows(AesEncryptionException.class, () -> aesEncryptionServiceImpl.encrypt(plainText));
    }
}
