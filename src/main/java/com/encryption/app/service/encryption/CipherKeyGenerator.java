package com.encryption.app.service.encryption;

import com.encryption.app.error.ErrorEncryptionException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

@Slf4j
@AllArgsConstructor
public class CipherKeyGenerator {

    private final String encryptionAlgorithm;
    private final CipherMode cipherMode;
    private final int iterations;
    private final int keySize;
    private final int saltSize;
    private final int nonceSize;

    public CipherSetup generateCipherSetup(String password, int mode) throws ErrorEncryptionException {
        log.info("Generate cipher setup");
        if (Objects.isNull(password) || password.isEmpty()) {
            throw new ErrorEncryptionException("Password cannot be null or empty");
        }

        byte[] salt = CryptoUtils.generateRandomBytes(saltSize);
        byte[] nonce = CryptoUtils.generateRandomBytes(nonceSize);

        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(encryptionAlgorithm, password, iterations, keySize, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), cipherMode.getAlgorithm());

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherMode.getTransformation());
            cipherMode.initCipher(cipher, mode, keySpec, nonce);
        } catch (Exception e) {
            throw new ErrorEncryptionException("Unforeseen error when creating Cipher", e);
        }

        return new CipherSetup(cipher, salt, nonce);
    }

    public CipherSetup loadCipherSetupForDecryption(InputStream in, String password) throws ErrorEncryptionException {
        log.info("Load cipher setup for decryption");
        if (Objects.isNull(password) || password.isEmpty()) {
            throw new ErrorEncryptionException("Password cannot be null or empty");
        }

        byte[] salt = new byte[saltSize];
        byte[] nonce = new byte[nonceSize];

        try {
            if (in.read(salt) != saltSize) {
                throw new ErrorEncryptionException("Unable to read salt from stream!");
            }

            if (in.read(nonce) != nonceSize) {
                throw new ErrorEncryptionException("Unable to read nonce from stream!");
            }
        } catch (IOException e) {
            throw new ErrorEncryptionException("Error reading salt/nonce from stream!", e);
        }

        SecretKey rawKey = CryptoUtils.generateKeyFromPassword(encryptionAlgorithm, password, iterations, keySize, salt);
        SecretKeySpec keySpec = new SecretKeySpec(rawKey.getEncoded(), cipherMode.getAlgorithm());
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(cipherMode.getTransformation());
            cipherMode.initCipher(cipher, Cipher.DECRYPT_MODE, keySpec, nonce);
        } catch (Exception e) {
            throw new ErrorEncryptionException("Unforeseen error when creating Cipher", e);
        }

        return new CipherSetup(cipher, salt, nonce);
    }
}