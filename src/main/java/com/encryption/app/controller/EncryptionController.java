package com.encryption.app.controller;

import com.encryption.app.dto.EncryptionRequestDTO;
import com.encryption.app.dto.EncryptionResponseDTO;
import com.encryption.app.service.EncryptingAndDecryptingFiles;
import com.encryption.app.service.file.FileEncryptionUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Objects;

@RestController("/v1")
@RequiredArgsConstructor
public class EncryptionController {

    private final Map<String, FileEncryptionUtil> fileEncryptionUtilMap;
    private final EncryptingAndDecryptingFiles encryptionAction;

    @PostMapping("/encryption")
    public ResponseEntity<?> encryptController(@RequestBody EncryptionRequestDTO encryptionDTO) {
        final EncryptionResponseDTO result = new EncryptionResponseDTO();
        String algorithm = encryptionDTO.getAlgorithm();
        FileEncryptionUtil fileEncryptionUtil = fileEncryptionUtilMap.get(algorithm);

        if (Objects.isNull(fileEncryptionUtil)) {
            result.setError("Unsupported algorithm: " + algorithm);
            return ResponseEntity.badRequest().body(result);
        }

         encryptionAction.encryptOrDecryptFiles(result, encryptionDTO, fileEncryptionUtil);

        if (Objects.isNull(result.getError())) {
            return ResponseEntity.ok(result);
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }
}