package com.encryption.app.service;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;

public class EncryptionServiceAesCtr {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 256; // Размер ключа 256 бит
    private static final int ITERATIONS = 65536; // Количество итераций для KDF
    private static final int SALT_SIZE = 16; // Размер соли
    private static final int NONCE_SIZE = 16; // Размер nonce (счётчика)

    // Генерация ключа из пароля
    private static SecretKey generateKeyFromPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec);
    }

//    // Генерация случайного nonce (счётчика)
//    public static byte[] generateNonce() {
//        byte[] nonce = new byte[NONCE_SIZE];
//        new SecureRandom().nextBytes(nonce);
//        return nonce;
//    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    // Шифрование файла с использованием AES-CTR
    public static void encryptFile(File inputFile, File outputFile, String password) throws Exception {
        // Генерируем соль и nonce
        byte[] salt = generateRandomBytes(SALT_SIZE);
        byte[] nonce = generateRandomBytes(NONCE_SIZE);

        // Генерируем ключ
        SecretKey rawKey = generateKeyFromPassword(password, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

        // Настраиваем шифр
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));

        try (FileOutputStream fos = new FileOutputStream(outputFile);
                CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            // 1) Запишем соль
            fos.write(salt);
            // 2) Запишем nonce
            fos.write(nonce);

            // 3) Шифруем содержимое
            try (FileInputStream fis = new FileInputStream(inputFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    public static void decryptFile(File inputFile, File outputFile, String password) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            // 1) Считываем соль
            byte[] salt = new byte[SALT_SIZE];
            fis.read(salt);

            // 2) Считываем nonce
            byte[] nonce = new byte[NONCE_SIZE];
            fis.read(nonce);

            // 3) Генерируем тот же ключ
            SecretKey rawKey = generateKeyFromPassword(password, salt);
            SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), ALGORITHM);

            // 4) Настраиваем шифр на расшифрование
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));

            try (
                    FileOutputStream fos = new FileOutputStream(outputFile);
                    CipherInputStream cis = new CipherInputStream(fis, cipher)
            ) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        File inputFile = new File("test_folder_start/images.jpg");
        File encryptedFile = new File("test_folder_finish/encrypted_image.enc");
        File decryptedFile = new File("test_folder_start/decrypted_image.jpg");

        String password = "your-secure-password";

        // Шифрование
//        encryptFile(inputFile, encryptedFile, password);
//        System.out.println("File encrypted.");

        encryptedFile.delete();

        // Дешифрование
        decryptFile(encryptedFile, decryptedFile, password);
        System.out.println("File decrypted.");
    }
}