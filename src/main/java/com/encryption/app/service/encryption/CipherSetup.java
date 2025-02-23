package com.encryption.app.service.encryption;

import javax.crypto.Cipher;

public record CipherSetup(Cipher cipher, byte[] salt, byte[] nonce) {
}