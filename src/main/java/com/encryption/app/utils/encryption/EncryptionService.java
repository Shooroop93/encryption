package com.encryption.app.utils.encryption;

import java.io.InputStream;
import java.io.OutputStream;

public interface EncryptionService {

    void encrypt(InputStream in, OutputStream out, String password) throws Exception;
    void decrypt(InputStream in, OutputStream out, String password) throws Exception;
}