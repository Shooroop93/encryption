package com.encryption.app.utils.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;

public class EncryptionServiceAesCtr implements EncryptionService {

    private final SaltNonceStreamHandler saltNonceStreamHandler;

    private final String ALGORITHM = "AES";
    private final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private final String ENCRYPTION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private final int KEY_SIZE = 256; // Размер ключа 256 бит
    private final int ITERATIONS = 65536; // Количество итераций для KDF
    private final int SALT_SIZE = 16; // Размер соли
    private final int NONCE_SIZE = 16; // Размер nonce (счётчика)

    public EncryptionServiceAesCtr(SaltNonceStreamHandler saltNonceStreamHandler) {
        this.saltNonceStreamHandler = saltNonceStreamHandler;
    }

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

        saltNonceStreamHandler.encryptStream(in, out, cipher, salt, nonce);
    }

    @Override
    public void decrypt(InputStream in, OutputStream out, String password) throws Exception {
        // Считываем соль
        byte[] salt = new byte[SALT_SIZE];
        in.read(salt);

        // Считываем nonce
        byte[] nonce = new byte[NONCE_SIZE];
        in.read(nonce);

        // Генерируем тот же ключ
        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(ENCRYPTION_ALGORITHM, password, ITERATIONS, KEY_SIZE, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // Настраиваем шифр на расшифрование
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));

        saltNonceStreamHandler.decryptStream(in, out, cipher);
    }
}