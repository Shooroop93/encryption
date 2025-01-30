package com.encryption.app.service.file;

import com.encryption.app.error.EncryptionException;

import java.io.File;

public interface FileEncryption {

    void encrypt(File in, File out, String password) throws EncryptionException;
    void decrypt(File in, File out, String password) throws EncryptionException;
}