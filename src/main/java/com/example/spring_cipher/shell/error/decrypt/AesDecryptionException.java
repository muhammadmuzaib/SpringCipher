package com.example.spring_cipher.shell.error.decrypt;

public class AesDecryptionException extends RuntimeException {
    public AesDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public AesDecryptionException(String message) {
        super(message);
    }

}
