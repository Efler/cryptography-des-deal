package org.eflerrr.padding.impl;

import org.eflerrr.padding.IPadding;

import java.util.Arrays;

public class ZerozPadding implements IPadding {

    @Override
    public byte[] makePadding(byte[] block, int size) {
        int n = block.length;
        int lengthPadding = size - (n % size);
        byte[] result = new byte[n + lengthPadding];
        System.arraycopy(block, 0, result, 0, n);
        return result;
    }

    @Override
    public byte[] undoPadding(byte[] block) {
        int i = block.length - 1;
        while (block[i] == 0) {
            i--;
        }
        return Arrays.copyOf(block, i + 1);
    }

}
