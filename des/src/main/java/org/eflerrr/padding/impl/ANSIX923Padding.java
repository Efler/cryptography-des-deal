package org.eflerrr.padding.impl;

import org.eflerrr.padding.IPadding;

import java.util.Arrays;

public class ANSIX923Padding implements IPadding {

    @Override
    public byte[] makePadding(byte[] block, int size) {
        int n = block.length;
        int lengthPadding = size - (n % size);
        byte[] result = new byte[n + lengthPadding];
        System.arraycopy(block, 0, result, 0, n);
        result[n + lengthPadding - 1] = (byte) lengthPadding;
        return result;
    }

    @Override
    public byte[] undoPadding(byte[] block) {
        return Arrays.copyOf(block, block.length - block[block.length - 1]);
    }

}
