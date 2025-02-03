package com.encryption.app.config;

import com.encryption.app.service.encryption.DefaultSaltNonceStreamHandler;
import com.encryption.app.service.encryption.EncryptionServiceAesCtr;
import com.encryption.app.service.encryption.EncryptionServiceAesGcm;
import com.encryption.app.service.file.FileEncryptionUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EncryptionConfig {

    @Bean("AES/CTR/NoPadding")
    public FileEncryptionUtil encryptionServiceAesCtr() {
        return new FileEncryptionUtil(new EncryptionServiceAesCtr(new DefaultSaltNonceStreamHandler()));
    }

    @Bean("AES/GCM/NoPadding")
    public FileEncryptionUtil encryptionServiceAesGsm() {
        return new FileEncryptionUtil(new EncryptionServiceAesGcm(new DefaultSaltNonceStreamHandler()));
    }
}