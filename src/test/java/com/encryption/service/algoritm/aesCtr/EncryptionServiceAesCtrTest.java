package com.encryption.service.algoritm.aesCtr;

import com.encryption.app.service.encryption.DefaultSaltNonceStreamHandler;
import com.encryption.app.service.encryption.EncryptionServiceAesCtr;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class EncryptionServiceAesCtrTest {

    @Test
    public void encryptAesCtrServiceStreamTest() throws Exception {

        String password = UUID.randomUUID().toString();
        String text = UUID.randomUUID().toString();

        byte[] resultEncryptStream = encryptStream(text, password);

        Assertions.assertNotEquals(text, new String(resultEncryptStream, StandardCharsets.UTF_8));
    }

    @Test
    public void decryptAesCtrServiceStreamTest() throws Exception {

        String password = UUID.randomUUID().toString();
        String text = UUID.randomUUID().toString();

        byte[] resultEncryptStream = encryptStream(text, password);
        byte[] resultDecryptStream = decryptStream(resultEncryptStream, password);

        Assertions.assertNotEquals(text, new String(resultEncryptStream, StandardCharsets.UTF_8));
        Assertions.assertEquals(text, new String(resultDecryptStream, StandardCharsets.UTF_8));
    }

    private byte[] decryptStream(byte[] encryptResult, String password) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptResult);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        EncryptionServiceAesCtr encryptionServiceAesCtr = new EncryptionServiceAesCtr(new DefaultSaltNonceStreamHandler());
        encryptionServiceAesCtr.decrypt(byteArrayInputStream, byteArrayOutputStream, password);

        return byteArrayOutputStream.toByteArray();
    }

    private byte[] encryptStream(String text, String password) throws Exception {
        InputStream inputStream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        EncryptionServiceAesCtr encryptionServiceAesCtr = new EncryptionServiceAesCtr(new DefaultSaltNonceStreamHandler());
        encryptionServiceAesCtr.encrypt(inputStream, outputStream, password);

        return outputStream.toByteArray();
    }
}