package com.encryption.app.service.file;

import com.encryption.app.error.ErrorEncryptionException;

import java.io.File;

public interface FileEncryption {

    void encrypt(File in, File out, String password) throws ErrorEncryptionException;
    void decrypt(File in, File out, String password) throws ErrorEncryptionException;
}