package com.encryption.app.utils.encryption;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Записываем salt и nonce внутри зашифрованного потока
 */
public class DefaultSaltNonceStreamHandler implements SaltNonceStreamHandler {

    @Override
    public void encryptStream(InputStream in, OutputStream out, Cipher cipher, byte[] salt, byte[] nonce) throws Exception {

        out.write(salt);
        out.write(nonce);

        try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    @Override
    public void decryptStream(InputStream in, OutputStream out, Cipher cipher) throws Exception {
        try (CipherInputStream cis = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
}