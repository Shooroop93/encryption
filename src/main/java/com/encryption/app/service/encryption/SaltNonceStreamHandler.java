package com.encryption.app.service.encryption;

import com.encryption.app.error.ErrorEncryptionException;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.io.OutputStream;

public interface SaltNonceStreamHandler {

    void encryptStream(InputStream in, OutputStream out, Cipher cipher, byte[] salt, byte[] nonce) throws ErrorEncryptionException;
    void decryptStream(InputStream in, OutputStream out, Cipher cipher) throws ErrorEncryptionException;
}