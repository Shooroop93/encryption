package com.encryption.app.utils.encryption;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class EncryptionServiceAesGcm implements EncryptionService {

    private final String ALGORITHM = "AES";
    private final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private final int KEY_SIZE = 256;       // Размер ключа 256 бит
    private final int ITERATIONS = 65536;   // Количество итераций для KDF
    private final int SALT_SIZE = 16;       // Размер соли
    // Для GCM обычно 12 байт IV (nonce) — рекомендуемый стандарт,
    // но если хочешь оставить 16 байт, можно и так.
    private final int NONCE_SIZE = 12;

    // Генерация ключа из пароля с помощью PBKDF2 (HmacSHA256)
    private SecretKey generateKeyFromPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec);
    }

    public byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    // =========================
    //  Шифрование (AES-GCM)
    // =========================
    @Override
    public void encrypt(InputStream in, OutputStream out, String password) throws Exception {
        // 1) Генерируем соль и nonce
        byte[] salt = generateRandomBytes(SALT_SIZE);
        byte[] nonce = generateRandomBytes(NONCE_SIZE);  // GCM nonce (обычно 12 байт)

        // 2) Генерируем ключ
        SecretKey rawKey = generateKeyFromPassword(password, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // 3) Настраиваем шифр AES/GCM/NoPadding
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // Параметры GCM: длина тэга аутентификации 128 бит, плюс nonce
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        // Запишем соль в начало
        out.write(salt);
        // Запишем nonce (IV) в начало (после соли)
        out.write(nonce);

        // 4) Создаём потоки для шифрования
        try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
            // 5) Шифруем содержимое входного файла
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    @Override
    public void decrypt(InputStream in, OutputStream out, String password) throws Exception {
        // 1) Открываем зашифрованный файл для чтения

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

        // 2) Генерируем тот же ключ из пароля и соли
        SecretKey rawKey = generateKeyFromPassword(password, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // 3) Настраиваем шифр AES/GCM/NoPadding для дешифрования
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        // 4) Создаём выходной файл и поток для расшифровки
        try (CipherInputStream cis = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
}
