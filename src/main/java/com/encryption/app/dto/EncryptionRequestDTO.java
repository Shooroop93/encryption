package com.encryption.app.dto;

import com.encryption.app.constant.EncryptionConstants;
import lombok.Data;

import java.util.List;

@Data
public class EncryptionRequestDTO {

    private EncryptionConstants action;
    private String algorithm;
    private String encryptionPathFolder;
    private List<String> pathFile;
    private String password;
    private int countThread;
}