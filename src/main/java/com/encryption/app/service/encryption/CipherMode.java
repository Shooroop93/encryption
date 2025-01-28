package com.encryption.app.service.encryption;

import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@AllArgsConstructor
@Getter
public enum CipherMode {

    GCM("AES/GCM/NoPadding", "AES") {
        @Override
        public void initCipher(Cipher cipher, int mode, SecretKeySpec keySpec, byte[] nonce) throws Exception {
            cipher.init(mode, keySpec, new GCMParameterSpec(128, nonce));
        }
    },

    CTR("AES/CTR/NoPadding", "AES") {
        @Override
        public void initCipher(Cipher cipher, int mode, SecretKeySpec keySpec, byte[] nonce) throws Exception {
            cipher.init(mode, keySpec, new IvParameterSpec(nonce));
        }
    };

    private final String transformation;
    private final String algorithm;

    public abstract void initCipher(Cipher cipher, int mode, SecretKeySpec keySpec, byte[] nonce) throws Exception;
}