package com.encryption.app.service.encryption;

import lombok.AllArgsConstructor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;

@AllArgsConstructor
public class CipherKeyGenerator {

    private final String encryptionAlgorithm;
    private final CipherMode cipherMode;
    private final int iterations;
    private final int keySize;
    private final int saltSize;
    private final int nonceSize;

    public CipherSetup generateCipherSetup(String password, int mode) throws Exception {
        byte[] salt = CryptoUtils.generateRandomBytes(saltSize);
        byte[] nonce = CryptoUtils.generateRandomBytes(nonceSize);

        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(encryptionAlgorithm, password, iterations, keySize, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), cipherMode.getAlgorithm());

        Cipher cipher = Cipher.getInstance(cipherMode.getTransformation());
        cipherMode.initCipher(cipher, mode, keySpec, nonce);

        return new CipherSetup(cipher, salt, nonce);
    }

    public CipherSetup loadCipherSetupForDecryption(InputStream in, String password) throws Exception {

        byte[] salt = new byte[saltSize];
        if (in.read(salt) != saltSize) {
            throw new IllegalStateException("Unable to read salt from file!");
        }

        byte[] nonce = new byte[nonceSize];
        if (in.read(nonce) != nonceSize) {
            throw new IllegalStateException("Unable to read nonce from file!");
        }

        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(encryptionAlgorithm, password, iterations, keySize, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(cipherMode.getTransformation());
        cipherMode.initCipher(cipher, Cipher.DECRYPT_MODE, keySpec, nonce);

        return new CipherSetup(cipher, salt, nonce);
    }
}