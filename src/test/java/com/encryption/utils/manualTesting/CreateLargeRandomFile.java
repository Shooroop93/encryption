package com.encryption.utils.manualTesting;

import java.io.File;
import java.io.FileOutputStream;
import java.security.SecureRandom;

public class CreateLargeRandomFile {

    private static final long FILE_SIZE = 107_374_182_400L; //
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String PATH = "PATH";

    public static void main(String[] args) throws Exception {
        File file = new File(PATH);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            SecureRandom random = new SecureRandom();
            byte[] buffer = new byte[BUFFER_SIZE];

            long bytesWritten = 0;
            while (bytesWritten < FILE_SIZE) {
                random.nextBytes(buffer);
                fos.write(buffer);
                bytesWritten += BUFFER_SIZE;

                if (bytesWritten % (10L * 1024 * 1024 * 1024) == 0) {
                    System.out.println("Writing " + (bytesWritten / (1024 * 1024 * 1024)) + " ГБ...");
                }
            }
        }
        System.out.println("File create: " + file.getAbsolutePath());
    }
}