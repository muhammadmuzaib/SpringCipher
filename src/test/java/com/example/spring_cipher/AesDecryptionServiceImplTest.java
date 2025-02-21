package com.example.spring_cipher;

import com.example.spring_cipher.core.service.AesDecryptionServiceImpl;
import com.example.spring_cipher.core.service.AesEncryptionServiceImpl;
import com.example.spring_cipher.shell.error.AesDecryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesDecryptionServiceImplTest {

    private AesDecryptionServiceImpl aesDecryptionServiceImpl;
    private AesEncryptionServiceImpl aesEncryptionServiceImpl;

    @BeforeEach
    void setUp() {
        //Given Decryption
        aesDecryptionServiceImpl = new AesDecryptionServiceImpl();
        ReflectionTestUtils.setField(aesDecryptionServiceImpl, "aesKey", "MySuperSecretKey");
        aesDecryptionServiceImpl.init();

        // Given Encryption
        aesEncryptionServiceImpl = new AesEncryptionServiceImpl();
        ReflectionTestUtils.setField(aesEncryptionServiceImpl, "aesKey", "MySuperSecretKey");
        aesEncryptionServiceImpl.init();
    }

    @Test
    void givenValidText_whenDecrypt_thenReturnsOriginalPlainText() {
        // Given
        String originalText = "HelloDecryption";
        String encrypted = aesEncryptionServiceImpl.encrypt(originalText);

        // When
        String decrypted = aesDecryptionServiceImpl.decrypt(encrypted);

        // Then
        assertEquals(originalText, decrypted, "Decrypted text should match the original");
    }

    @Test
    void givenNullText_whenDecrypt_thenThrowsAesDecryptionException() {
        // Given
        String cipherText = null;

        //Then
        assertThrows(AesDecryptionException.class, () -> aesDecryptionServiceImpl.decrypt(cipherText));
    }

    @Test
    void givenEmptyText_whenDecrypt_thenThrowsAesDecryptionException() {
        // Given
        String cipherText = "";

        // Then
        assertThrows(AesDecryptionException.class, () -> aesDecryptionServiceImpl.decrypt(cipherText));
    }
}
