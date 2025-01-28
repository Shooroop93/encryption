package com.encryption.app.utils.file;

import com.encryption.app.utils.encryption.EncryptionService;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class FileEncryptionUtil implements FileEncryption {

    private final EncryptionService encryptionService;

    public FileEncryptionUtil(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @Override
    public void encrypt(File in, File out, String password) throws Exception {
        try (FileInputStream fileInputStream = new FileInputStream(in);
             FileOutputStream fileOutputStream = new FileOutputStream(out)) {
            encryptionService.encrypt(fileInputStream, fileOutputStream, password);
        }
    }

    @Override
    public void decrypt(File in, File out, String password) throws Exception {
        try (FileInputStream fileInputStream = new FileInputStream(in);
             FileOutputStream fileOutputStream = new FileOutputStream(out)) {
            encryptionService.decrypt(fileInputStream, fileOutputStream, password);
        }
    }
}
