package com.encryption.utils.manualTesting;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

public class FileComparator {

    public static boolean compareFiles(File file1, File file2) throws IOException {
        try (FileInputStream fis1 = new FileInputStream(file1);
             FileInputStream fis2 = new FileInputStream(file2)) {

            byte[] buffer1 = new byte[64 * 1024];
            byte[] buffer2 = new byte[64 * 1024];

            int bytesRead1, bytesRead2;
            while ((bytesRead1 = fis1.read(buffer1)) != -1) {
                bytesRead2 = fis2.read(buffer2);
                if (bytesRead1 != bytesRead2 || !Arrays.equals(buffer1, buffer2)) {
                    return false;
                }
            }
            return fis2.read() == -1;
        }
    }
}
