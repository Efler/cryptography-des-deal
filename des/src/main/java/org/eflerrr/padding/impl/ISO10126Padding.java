package org.eflerrr.padding.impl;

import org.eflerrr.padding.IPadding;

import java.security.SecureRandom;
import java.util.Arrays;

public class ISO10126Padding implements IPadding {

    @Override
    public byte[] makePadding(byte[] block, int size) {
        int n = block.length;
        int lengthPadding = size - (block.length % size);
        byte[] paddingBytes = new byte[lengthPadding];
        new SecureRandom().nextBytes(paddingBytes);
        paddingBytes[lengthPadding - 1] = (byte) lengthPadding;
        byte[] result = new byte[n + lengthPadding];
        System.arraycopy(block, 0, result, 0, n);
        System.arraycopy(paddingBytes, 0, result, n, lengthPadding);
        return result;
    }

    @Override
    public byte[] undoPadding(byte[] block) {
        return Arrays.copyOf(block, block.length - block[block.length - 1]);
    }

}
