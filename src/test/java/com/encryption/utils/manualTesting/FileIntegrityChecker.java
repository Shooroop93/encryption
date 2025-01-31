package com.encryption.utils.manualTesting;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

public class FileIntegrityChecker {

    public static String calculateSHA256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        StringBuilder hexString = new StringBuilder();
        for (byte b : digest.digest()) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}