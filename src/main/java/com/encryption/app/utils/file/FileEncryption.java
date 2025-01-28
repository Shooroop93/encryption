package com.encryption.app.utils.file;

import java.io.File;

public interface FileEncryption {

    void encrypt(File in, File out, String password) throws Exception;
    void decrypt(File in, File out, String password) throws Exception;
}