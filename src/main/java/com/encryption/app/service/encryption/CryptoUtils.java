package com.encryption.app.service.encryption;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

public class CryptoUtils {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static SecretKey generateKeyFromPassword(String encryptionAlgorithm,
                                                    String password,
                                                    int iterations,
                                                    int keySize,
                                                    byte... salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(encryptionAlgorithm);
        return factory.generateSecret(spec);
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}