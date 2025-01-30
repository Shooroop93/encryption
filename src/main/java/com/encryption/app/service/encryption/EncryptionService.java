package com.encryption.app.service.encryption;

import com.encryption.app.error.EncryptionException;

import java.io.InputStream;
import java.io.OutputStream;

public interface EncryptionService {

    void encrypt(InputStream in, OutputStream out, String password) throws EncryptionException;
    void decrypt(InputStream in, OutputStream out, String password) throws EncryptionException;
}