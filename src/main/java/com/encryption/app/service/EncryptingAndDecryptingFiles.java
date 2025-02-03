package com.encryption.app.service;

import com.encryption.app.dto.EncryptionRequestDTO;
import com.encryption.app.dto.EncryptionResponseDTO;
import com.encryption.app.error.EncryptionException;
import com.encryption.app.service.file.FileEncryptionUtil;
import com.encryption.app.utils.FileUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.encryption.app.utils.FileUtil.createAFolderForTheResult;

@Slf4j
@Service
public class EncryptingAndDecryptingFiles {

    public EncryptionResponseDTO encryptOrDecryptFiles(EncryptionResponseDTO result,
                                                       EncryptionRequestDTO encryptionDTO,
                                                       FileEncryptionUtil fileEncryptionUtil) {
        File currentDirectory = new File(encryptionDTO.getEncryptionPathFolder());

        if (!currentDirectory.exists() || !currentDirectory.isDirectory()) {
            result.setError("The specified directory does not exist or is not a directory");
            return result;
        }

        File pathDirectoryResultEncryption = null;

        ExecutorService executor = Executors.newFixedThreadPool(encryptionDTO.getCountThread());
        try {
            switch (encryptionDTO.getAction()) {
                case ENCRYPTION -> {
                    pathDirectoryResultEncryption = createAFolderForTheResult(currentDirectory, "encryption", "yyyy-MM-dd'T'HH-mm-ss");
                    encryptionFiles(fileEncryptionUtil, encryptionDTO, currentDirectory, pathDirectoryResultEncryption, executor);
                }
                case DECRYPTION -> {
                    pathDirectoryResultEncryption = createAFolderForTheResult(currentDirectory, "decryption", "yyyy-MM-dd'T'HH-mm-ss");
                    decryptionFiles(fileEncryptionUtil, encryptionDTO, currentDirectory, pathDirectoryResultEncryption, executor);
                }
                default -> {
                    result.setError("Unknown type of action");
                    return result;
                }
            }
            executor.shutdown();
            if (!executor.awaitTermination(1, TimeUnit.HOURS)) {
                log.warn("Not all tasks finished within the timeout");
            }
        } catch (EncryptionException | InterruptedException e) {
            result.setError(e.getMessage());
            try {
                FileUtil.deleteDirectory(pathDirectoryResultEncryption);
            } catch (EncryptionException ex) {
                result.setError(ex.getMessage());
            }
            executor.shutdownNow();
            return result;
        }
        result.setPathResult(pathDirectoryResultEncryption.getAbsolutePath());
        return result;
    }

    private void encryptionFiles(FileEncryptionUtil fileEncryptionUtil,
                                 EncryptionRequestDTO encryptionDTO,
                                 File currentSourceDir,
                                 File currentDestDir,
                                 ExecutorService executor) throws EncryptionException {
        File[] files = currentSourceDir.listFiles();

        if (files != null) {
            List<Future<?>> futures = new ArrayList<>();

            for (File file : files) {
                if (file.isDirectory()) {
                    File newDestDir = new File(currentDestDir, file.getName());
                    if (!newDestDir.exists() && !newDestDir.mkdir()) {
                        throw new EncryptionException("Failed to create a directory: " + newDestDir.getAbsolutePath());
                    }
                    encryptionFiles(fileEncryptionUtil, encryptionDTO, file, newDestDir, executor);
                } else {
                    Future<?> future = executor.submit(() -> {
                        try {
                            File outFile = new File(currentDestDir, file.getName());
                            fileEncryptionUtil.encrypt(file, outFile, encryptionDTO.getPassword());
                        } catch (EncryptionException e) {
                            log.error("Error encrypting file: {}", file.getAbsolutePath(), e);
                            throw new RuntimeException(e);
                        }
                    });
                    futures.add(future);
                }
            }
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new EncryptionException("Error during encryption in multithreaded execution", e);
                }
            }
        }
    }

    private void decryptionFiles(FileEncryptionUtil fileEncryptionUtil,
                                 EncryptionRequestDTO encryptionDTO,
                                 File currentSourceDir,
                                 File currentDestDir,
                                 ExecutorService executor) throws EncryptionException {
        File[] files = currentSourceDir.listFiles();

        if (files != null) {
            List<Future<?>> futures = new ArrayList<>();

            for (File file : files) {
                if (file.isDirectory()) {
                    File newDestDir = new File(currentDestDir, file.getName());
                    if (!newDestDir.exists() && !newDestDir.mkdir()) {
                        throw new EncryptionException("Failed to create a directory: " + newDestDir.getAbsolutePath());
                    }
                    decryptionFiles(fileEncryptionUtil, encryptionDTO, file, newDestDir, executor);
                } else {
                    Future<?> future = executor.submit(() -> {
                        try {
                            File outFile = new File(currentDestDir, file.getName());
                            fileEncryptionUtil.decrypt(file, outFile, encryptionDTO.getPassword());
                        } catch (EncryptionException e) {
                            log.error("Error decrypting file: {}", file.getAbsolutePath(), e);
                            throw new RuntimeException(e);
                        }
                    });
                    futures.add(future);
                }
            }
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new EncryptionException("Error during decryption in multithreaded execution", e);
                }
            }
        }
    }
}