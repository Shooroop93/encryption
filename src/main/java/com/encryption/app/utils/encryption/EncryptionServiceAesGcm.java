package com.encryption.app.utils.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;

public class EncryptionServiceAesGcm implements EncryptionService {

    private final SaltNonceStreamHandler saltNonceStreamHandler;

    private final String ALGORITHM = "AES";
    private final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private final String ENCRYPTION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private final int KEY_SIZE = 256;       // Размер ключа 256 бит
    private final int ITERATIONS = 65536;   // Количество итераций для KDF
    private final int SALT_SIZE = 16;       // Размер соли
    // Для GCM обычно 12 байт IV (nonce) — рекомендуемый стандарт,
    // но если хочешь оставить 16 байт, можно и так.
    private final int NONCE_SIZE = 12;

    public EncryptionServiceAesGcm(SaltNonceStreamHandler saltNonceStreamHandler) {
        this.saltNonceStreamHandler = saltNonceStreamHandler;
    }

    // =========================
    //  Шифрование (AES-GCM)
    // =========================
    @Override
    public void encrypt(InputStream in, OutputStream out, String password) throws Exception {
        // 1) Генерируем соль и nonce
        byte[] salt = CryptoUtils.generateRandomBytes(SALT_SIZE);
        byte[] nonce = CryptoUtils.generateRandomBytes(NONCE_SIZE);  // GCM nonce (обычно 12 байт)

        // 2) Генерируем ключ
        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(ENCRYPTION_ALGORITHM, password, ITERATIONS, KEY_SIZE, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // 3) Настраиваем шифр AES/GCM/NoPadding
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // Параметры GCM: длина тэга аутентификации 128 бит, плюс nonce
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        saltNonceStreamHandler.encryptStream(in, out, cipher, salt, nonce);
    }

    @Override
    public void decrypt(InputStream in, OutputStream out, String password) throws Exception {
        // Считываем соль
        byte[] salt = new byte[SALT_SIZE];
        if (in.read(salt) != SALT_SIZE) {
            throw new IllegalStateException("Unable to read salt from file!");
        }

        // Считываем nonce
        byte[] nonce = new byte[NONCE_SIZE];
        if (in.read(nonce) != NONCE_SIZE) {
            throw new IllegalStateException("Unable to read nonce from file!");
        }

        // Генерируем тот же ключ из пароля и соли
        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(ENCRYPTION_ALGORITHM, password, ITERATIONS, KEY_SIZE, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // Настраиваем шифр для дешифрования
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        saltNonceStreamHandler.decryptStream(in, out, cipher);
    }
}
