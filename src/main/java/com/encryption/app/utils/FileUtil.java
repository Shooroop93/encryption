package com.encryption.app.utils;

import com.encryption.app.error.EncryptionException;

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class FileUtil {

    public static boolean deleteDirectory(File directory) throws EncryptionException {
        if (directory.exists()) {
            if (directory.isDirectory()) {
                File[] files = directory.listFiles();
                if (files != null) {
                    for (File file : files) {
                        boolean success = deleteDirectory(file);
                        if (!success) {
                            throw new EncryptionException("Failed to delete: " + file.getAbsolutePath());
                        }
                    }
                }
            }
            return directory.delete();
        }
        return false;
    }

    public static File createAFolderForTheResult(File directory, String nameDirectory, String pattern) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
        String pathResult = String.format("%s/%s_%s", directory.getParent(), nameDirectory, LocalDateTime.now().format(formatter));
        File resulDirectory = new File(pathResult);
        resulDirectory.mkdir();
        return resulDirectory;
    }
}
