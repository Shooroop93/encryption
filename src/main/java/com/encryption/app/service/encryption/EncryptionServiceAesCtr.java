package com.encryption.app.service.encryption;

import com.encryption.app.error.EncryptionException;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public class EncryptionServiceAesCtr implements EncryptionService {

    private final String ENCRYPTION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private final int KEY_SIZE = 256; // Размер ключа 256 бит
    private final int ITERATIONS = 65536; // Количество итераций для KDF
    private final int SALT_SIZE = 16; // Размер соли
    private final int NONCE_SIZE = 16; // Размер nonce (счётчика)
    private final String CIPHER_PROVIDER = "BC";

    private final SaltNonceStreamHandler saltNonceStreamHandler;

    private final CipherKeyGenerator cipherKeyGenerator =
            new CipherKeyGenerator(ENCRYPTION_ALGORITHM, CipherMode.GCM, ITERATIONS, KEY_SIZE, SALT_SIZE, NONCE_SIZE, CIPHER_PROVIDER);

    public EncryptionServiceAesCtr(SaltNonceStreamHandler saltNonceStreamHandler) {
        this.saltNonceStreamHandler = saltNonceStreamHandler;
    }

    @Override
    public void encrypt(InputStream in, OutputStream out, String password) throws EncryptionException {
        if (Objects.isNull(password) || password.isEmpty()) {
            throw new EncryptionException("Password cannot be null or empty");
        }
        CipherSetup cipherSetup = cipherKeyGenerator.generateCipherSetup(password, Cipher.ENCRYPT_MODE);
        saltNonceStreamHandler.encryptStream(in, out, cipherSetup.cipher(), cipherSetup.salt(), cipherSetup.nonce());
    }

    @Override
    public void decrypt(InputStream in, OutputStream out, String password) throws EncryptionException {
        if (Objects.isNull(password) || password.isEmpty()) {
            throw new EncryptionException("Password cannot be null or empty");
        }
        CipherSetup cipherSetup = cipherKeyGenerator.loadCipherSetupForDecryption(in, password);
        saltNonceStreamHandler.decryptStream(in, out, cipherSetup.cipher());
    }
}