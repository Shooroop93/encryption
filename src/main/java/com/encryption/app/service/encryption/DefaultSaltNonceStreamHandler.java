package com.encryption.app.service.encryption;

import com.encryption.app.error.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class DefaultSaltNonceStreamHandler implements SaltNonceStreamHandler {

    private static final int BUFFER_SIZE = 64 * 1024;

    @Override
    public void encryptStream(InputStream in, OutputStream out, Cipher cipher, byte[] salt, byte[] nonce) throws EncryptionException {
        try {
            out.write(salt);
            out.write(nonce);
            out.flush(); //

            try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
                cos.flush(); //
            }
        } catch (IOException e) {
            throw new EncryptionException("There is a problem when writing encrypted data to the stream", e);
        }
    }

    @Override
    public void decryptStream(InputStream in, OutputStream out, Cipher cipher) throws EncryptionException {
        try {
            try (CipherInputStream cis = new CipherInputStream(in, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                out.flush(); //
            }
        } catch (IOException e) {
            throw new EncryptionException("There is a problem when writing decrypted data to the stream", e);
        }
    }
}