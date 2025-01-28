package com.encryption.app.utils.encryption;

import javax.crypto.Cipher;

public record CipherSetup(Cipher cipher, byte[] salt, byte[] nonce) {
}