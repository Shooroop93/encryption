package com.encryption.app.utils.encryption;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;

public class EncryptionServiceAesCtr implements EncryptionService {

    private final String ALGORITHM = "AES";
    private final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private final String ENCRYPTION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private final int KEY_SIZE = 256; // Размер ключа 256 бит
    private final int ITERATIONS = 65536; // Количество итераций для KDF
    private final int SALT_SIZE = 16; // Размер соли
    private final int NONCE_SIZE = 16; // Размер nonce (счётчика)


    @Override
    public void encrypt(InputStream in, OutputStream out, String password) throws Exception {
        // Генерируем соль и nonce
        byte[] salt = CryptoUtils.generateRandomBytes(SALT_SIZE);
        byte[] nonce = CryptoUtils.generateRandomBytes(NONCE_SIZE);

        // Генерируем ключ
        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(ENCRYPTION_ALGORITHM, password, ITERATIONS, KEY_SIZE, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // Настраиваем шифр
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
        // 1) Запишем соль
        out.write(salt);
        // 2) Запишем nonce
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
    public void decrypt(InputStream in, OutputStream out, String password) throws Exception {
        // 1) Считываем соль
        byte[] salt = new byte[SALT_SIZE];
        in.read(salt);

        // 2) Считываем nonce
        byte[] nonce = new byte[NONCE_SIZE];
        in.read(nonce);

        // 3) Генерируем тот же ключ
        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(ENCRYPTION_ALGORITHM, password, ITERATIONS, KEY_SIZE, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // 4) Настраиваем шифр на расшифрование
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));

        try (CipherInputStream cis = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
}