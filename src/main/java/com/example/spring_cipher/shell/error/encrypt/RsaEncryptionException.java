package com.example.spring_cipher.shell.error.encrypt;

public class RsaEncryptionException extends RuntimeException {
    public RsaEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
    public RsaEncryptionException(String message) {
        super(message);
    }
}
