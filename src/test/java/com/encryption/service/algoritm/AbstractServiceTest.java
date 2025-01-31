package com.encryption.service.algoritm;

import com.encryption.app.error.EncryptionException;
import com.encryption.app.service.encryption.EncryptionService;
import org.junit.jupiter.api.Assertions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public abstract class AbstractServiceTest {

    protected EncryptionService encryptionService;

    protected byte[] decryptStream(byte[] encryptResult, String password) throws EncryptionException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptResult);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        encryptionService.decrypt(byteArrayInputStream, byteArrayOutputStream, password);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] encryptStream(String text, String password) throws EncryptionException {
        InputStream inputStream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        encryptionService.encrypt(inputStream, outputStream, password);
        return outputStream.toByteArray();
    }

    protected void testEncoding(String originalText, Charset charset, String encodingName) throws EncryptionException {
        String password = UUID.randomUUID().toString();

        byte[] originalBytes = originalText.getBytes(charset);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(originalBytes);
        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
        encryptionService.encrypt(inputStream, encryptedOutput, password);
        byte[] encryptedBytes = encryptedOutput.toByteArray();

        ByteArrayInputStream encryptedInput = new ByteArrayInputStream(encryptedBytes);
        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
        encryptionService.decrypt(encryptedInput, decryptedOutput, password);
        byte[] decryptedBytes = decryptedOutput.toByteArray();
        String decryptedText = new String(decryptedBytes, charset);

        Assertions.assertEquals(
                originalText,
                decryptedText,
                "The text after encryption/decryption in encoding " + encodingName + " must match the original text"
        );
    }
}