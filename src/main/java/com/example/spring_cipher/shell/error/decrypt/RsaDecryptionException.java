package com.example.spring_cipher.shell.error.decrypt;

public class RsaDecryptionException extends RuntimeException {
    public RsaDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
    public RsaDecryptionException(String message) {
        super(message);
    }
}
