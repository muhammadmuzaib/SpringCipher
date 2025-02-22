package com.example.spring_cipher.shell.dto;

public class RsaEncryptedPayload {

    private String encryptedData;
    private String signature;

    public RsaEncryptedPayload(String encryptedData, String signature) {
        this.encryptedData = encryptedData;
        this.signature = signature;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public String getSignature() {
        return signature;
    }
}
