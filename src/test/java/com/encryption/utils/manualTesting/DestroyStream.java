package com.encryption.utils.manualTesting;

import java.util.Random;

public class DestroyStream {

    public static void corruptEncryptedArray(byte[] bytes, int offset, int length) {

        if (offset < 0 || offset + length > bytes.length) {
            throw new IllegalArgumentException("Incorrect offset/length. Number of bytes less than requested");
        }

        for (int i = offset; i < offset + length; i++) {
            bytes[i] = (byte) new Random().nextInt(256);
        }
    }
}