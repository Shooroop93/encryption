package com.encryption.app.service;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;


public class EncryptionServiceAesGcm {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;       // Размер ключа 256 бит
    private static final int ITERATIONS = 65536;   // Количество итераций для KDF
    private static final int SALT_SIZE = 16;       // Размер соли
    // Для GCM обычно 12 байт IV (nonce) — рекомендуемый стандарт,
    // но если хочешь оставить 16 байт, можно и так.
    private static final int NONCE_SIZE = 12;      // Лучше 12 байт для GCM

    // Генерация ключа из пароля с помощью PBKDF2 (HmacSHA256)
    private static SecretKey generateKeyFromPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec);
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    // =========================
    //  Шифрование (AES-GCM)
    // =========================
    public static void encryptFile(File inputFile, File outputFile, String password) throws Exception {
        // 1) Генерируем соль и nonce
        byte[] salt  = generateRandomBytes(SALT_SIZE);
        byte[] nonce = generateRandomBytes(NONCE_SIZE);  // GCM nonce (обычно 12 байт)

        // 2) Генерируем ключ
        SecretKey rawKey = generateKeyFromPassword(password, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // 3) Настраиваем шифр AES/GCM/NoPadding
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // Параметры GCM: длина тэга аутентификации 128 бит, плюс nonce
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        // 4) Создаём выходной файл и потоки для шифрования
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            // Запишем соль в начало
            fos.write(salt);
            // Запишем nonce (IV) в начало (после соли)
            fos.write(nonce);

            // 5) Шифруем содержимое входного файла
            try (FileInputStream fis = new FileInputStream(inputFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    // =========================
    //  Дешифрование (AES-GCM)
    // =========================
    public static void decryptFile(File inputFile, File outputFile, String password) throws Exception {
        // 1) Открываем зашифрованный файл для чтения
        try (FileInputStream fis = new FileInputStream(inputFile)) {

            // Считываем соль
            byte[] salt = new byte[SALT_SIZE];
            if (fis.read(salt) != SALT_SIZE) {
                throw new IllegalStateException("Unable to read salt from file!");
            }

            // Считываем nonce
            byte[] nonce = new byte[NONCE_SIZE];
            if (fis.read(nonce) != NONCE_SIZE) {
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
            try (FileOutputStream fos = new FileOutputStream(outputFile);
                 CipherInputStream cis = new CipherInputStream(fis, cipher)) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        File inputFile     = new File("test_folder_start/images.jpg");
        File encryptedFile = new File("test_folder_finish/encrypted_image.enc");
        File decryptedFile = new File("test_folder_start/decrypted_image.jpg");

        String password = "your-secure-password";

        // Шифрование
//        encryptFile(inputFile, encryptedFile, password);
        System.out.println("File encrypted (AES-GCM).");

        // Дешифрование
        decryptFile(encryptedFile, decryptedFile, password);
        System.out.println("File decrypted (AES-GCM).");
    }
}
