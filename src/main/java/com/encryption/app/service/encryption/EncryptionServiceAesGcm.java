package com.encryption.app.service.encryption;

import com.encryption.app.error.EncryptionException;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.io.OutputStream;

public class EncryptionServiceAesGcm implements EncryptionService {

    private final SaltNonceStreamHandler saltNonceStreamHandler;

    private final String ENCRYPTION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private final int KEY_SIZE = 256;       // Размер ключа 256 бит
    private final int ITERATIONS = 65536;   // Количество итераций для KDF
    private final int SALT_SIZE = 16;       // Размер соли
    // Для GCM обычно 12 байт IV (nonce) — рекомендуемый стандарт
    private final int NONCE_SIZE = 12;
    private final String CIPHER_PROVIDER = "BC";

    private final CipherKeyGenerator cipherKeyGenerator =
            new CipherKeyGenerator(ENCRYPTION_ALGORITHM, CipherMode.GCM, ITERATIONS, KEY_SIZE, SALT_SIZE, NONCE_SIZE, CIPHER_PROVIDER);

    public EncryptionServiceAesGcm(SaltNonceStreamHandler saltNonceStreamHandler) {
        this.saltNonceStreamHandler = saltNonceStreamHandler;
    }

    @Override
    public void encrypt(InputStream in, OutputStream out, String password) throws EncryptionException {
        CipherSetup cipherSetup = cipherKeyGenerator.generateCipherSetup(password, Cipher.ENCRYPT_MODE);
        saltNonceStreamHandler.encryptStream(in, out, cipherSetup.cipher(), cipherSetup.salt(), cipherSetup.nonce());
    }

    @Override
    public void decrypt(InputStream in, OutputStream out, String password) throws EncryptionException {
        CipherSetup cipherSetup = cipherKeyGenerator.loadCipherSetupForDecryption(in, password);
        saltNonceStreamHandler.decryptStream(in, out, cipherSetup.cipher());
    }
}