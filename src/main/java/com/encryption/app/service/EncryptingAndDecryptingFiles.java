package com.encryption.app.service;

import com.encryption.app.dto.EncryptionRequestDTO;
import com.encryption.app.dto.EncryptionResponseDTO;
import com.encryption.app.error.EncryptionException;
import com.encryption.app.service.file.FileEncryptionUtil;
import com.encryption.app.utils.FileUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;

import static com.encryption.app.utils.FileUtil.createAFolderForTheResult;

@Slf4j
@Service
public class EncryptingAndDecryptingFiles {

    public EncryptionResponseDTO encryptOrDecryptFiles(EncryptionResponseDTO result, EncryptionRequestDTO encryptionDTO, FileEncryptionUtil fileEncryptionUtil) {
        File currentDirectory = new File(encryptionDTO.getEncryptionPathFolder());

        if (currentDirectory.exists() && currentDirectory.isDirectory()) {
            File pathDirectoryResultEncryption = null;
            try {
                switch (encryptionDTO.getAction()) {
                    case ENCRYPTION -> {
                        pathDirectoryResultEncryption = createAFolderForTheResult(currentDirectory, "encryption", "yyyy-MM-dd'T'HH-mm-ss");
                        encryptionFiles(fileEncryptionUtil, encryptionDTO, currentDirectory, pathDirectoryResultEncryption);
                    }
                    case DECRYPTION -> {
                        pathDirectoryResultEncryption = createAFolderForTheResult(currentDirectory, "decryption", "yyyy-MM-dd'T'HH-mm-ss");
                        decryptionFiles(fileEncryptionUtil, encryptionDTO, currentDirectory, pathDirectoryResultEncryption);
                    }
                    default -> {
                        result.setError("Unknown type of action");
                        return result;
                    }
                }

            } catch (EncryptionException e) {
                result.setError(e.getMessage());
                try {
                    FileUtil.deleteDirectory(pathDirectoryResultEncryption);
                } catch (EncryptionException ex) {
                    result.setError(ex.getMessage());
                }
                return result;
            }
            result.setPathResult(pathDirectoryResultEncryption.getAbsolutePath());
        } else {
            result.setError("The specified directory does not exist or is not a directory");
        }

        return result;
    }

    private void decryptionFiles(FileEncryptionUtil fileEncryptionUtil,
                                 EncryptionRequestDTO encryptionDTO,
                                 File currentSourceDir,
                                 File currentDestDir) throws EncryptionException {
        File[] files = currentSourceDir.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    File newDestDir = new File(currentDestDir, file.getName());
                    if (!newDestDir.exists() && !newDestDir.mkdir()) {
                        throw new EncryptionException("Failed to create a directory: " + newDestDir.getAbsolutePath());
                    }
                    decryptionFiles(fileEncryptionUtil, encryptionDTO, file, newDestDir);
                } else {
                    File outFile = new File(currentDestDir, file.getName());
                    fileEncryptionUtil.decrypt(file, outFile, encryptionDTO.getPassword());
                }
            }
        }
    }

    private void encryptionFiles(FileEncryptionUtil fileEncryptionUtil,
                                 EncryptionRequestDTO encryptionDTO,
                                 File currentSourceDir,
                                 File currentDestDir) throws EncryptionException {
        File[] files = currentSourceDir.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    File newDestDir = new File(currentDestDir, file.getName());
                    if (!newDestDir.exists() && !newDestDir.mkdir()) {
                        throw new EncryptionException("Failed to create a directory: " + newDestDir.getAbsolutePath());
                    }
                    encryptionFiles(fileEncryptionUtil, encryptionDTO, file, newDestDir);
                } else {
                    File outFile = new File(currentDestDir, file.getName());
                    fileEncryptionUtil.encrypt(file, outFile, encryptionDTO.getPassword());
                }
            }
        }
    }
}