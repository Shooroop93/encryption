package com.encryption.app.service.file;

import com.encryption.app.error.EncryptionException;
import com.encryption.app.service.encryption.EncryptionService;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

@Slf4j
public class FileEncryptionUtil implements FileEncryption {

    private final EncryptionService encryptionService;

    public FileEncryptionUtil(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @Override
    public void encrypt(File in, File out, String password) throws EncryptionException {
        try (FileInputStream fileInputStream = new FileInputStream(in);
             FileOutputStream fileOutputStream = new FileOutputStream(out)) {
            encryptionService.encrypt(fileInputStream, fileOutputStream, password);
        } catch (Exception e) {
            throw new EncryptionException("There is a problem when encrypting a file", e);
        }
    }

    @Override
    public void decrypt(File in, File out, String password) throws EncryptionException {
        try (FileInputStream fileInputStream = new FileInputStream(in);
             FileOutputStream fileOutputStream = new FileOutputStream(out)) {
            encryptionService.decrypt(fileInputStream, fileOutputStream, password);
        } catch (Exception e) {
            throw new EncryptionException("There is a problem when decrypt a file", e);
        }
    }
}
