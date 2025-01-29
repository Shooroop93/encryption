package com.encryption.service.algoritm.aesGcm;

import com.encryption.app.service.encryption.DefaultSaltNonceStreamHandler;
import com.encryption.app.service.encryption.EncryptionServiceAesCtr;
import com.encryption.app.service.encryption.EncryptionServiceAesGcm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class EncryptionServiceAesGcmTest {

    @Test
    public void encryptAesGcmServiceStreamTest() throws Exception {

        String password = UUID.randomUUID().toString();
        String text = UUID.randomUUID().toString();

        byte[] resultEncryptStream = encryptStream(text, password);

        Assertions.assertNotEquals(text, new String(resultEncryptStream, StandardCharsets.UTF_8));
    }

    @Test
    public void decryptAesGcmServiceStreamTest() throws Exception {

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

        EncryptionServiceAesGcm encryptionServiceAesGcm = new EncryptionServiceAesGcm(new DefaultSaltNonceStreamHandler());
        encryptionServiceAesGcm.decrypt(byteArrayInputStream, byteArrayOutputStream, password);

        return byteArrayOutputStream.toByteArray();
    }

    private byte[] encryptStream(String text, String password) throws Exception {
        InputStream inputStream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        EncryptionServiceAesGcm encryptionServiceAesGsm = new EncryptionServiceAesGcm(new DefaultSaltNonceStreamHandler());
        encryptionServiceAesGsm.encrypt(inputStream, outputStream, password);

        return outputStream.toByteArray();
    }
}