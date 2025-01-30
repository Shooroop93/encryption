package com.encryption.app.service.encryption;

import com.encryption.app.error.EncryptionException;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import static java.lang.String.format;

@Slf4j
public class CryptoUtils {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static SecretKey generateKeyFromPassword(String encryptionAlgorithm,
                                                    String password,
                                                    int iterations,
                                                    int keySize,
                                                    byte... salt) throws EncryptionException {
        if (Objects.isNull(password) || password.isEmpty()) {
            throw new EncryptionException("Password cannot be null or empty");
        }

        log.info("Generate key from password");
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
            SecretKeyFactory factory = null;
            factory = SecretKeyFactory.getInstance(encryptionAlgorithm);
            return factory.generateSecret(spec);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException(format("algorithm %s is missing", encryptionAlgorithm), e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("key specification is inappropriate for this secret-key factory to produce a secret key", e);
        }
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}