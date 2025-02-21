package com.example.spring_cipher.shell.error;

public class AesEncryptionException extends RuntimeException {
    public AesEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public AesEncryptionException(String message) {
        super(message);
    }
}
