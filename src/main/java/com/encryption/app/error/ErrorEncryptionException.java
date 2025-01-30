package com.encryption.app.error;

public class ErrorEncryptionException extends Exception {

    public ErrorEncryptionException(String message) {
        super(message);
    }

    public ErrorEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
