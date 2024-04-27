package org.eflerrr.utils;

import static org.eflerrr.config.SubstitutionConfig.S_BLOCKS;

public class Utils {

    public static byte[] permutation(
            byte[] block, int[] pBlock, boolean reversedOrder, boolean isOneIndexed
    ) {
        if (block == null || pBlock == null) {
            throw new NullPointerException("Blocks cannot be null!");
        }

        byte[] res = new byte[(pBlock.length + 7) / 8];
        int currBitIndex = 0;

        for (var i : pBlock) {
            int position = i - (isOneIndexed ? 1 : 0);
            int bitOffset = reversedOrder ? position % 8 : 7 - position % 8;
            int resOffset = 7 - currBitIndex % 8;
            int blockIndex = position / 8;
            if (blockIndex >= block.length) {
                throw new IndexOutOfBoundsException(String.format("P-block index %d is out of bounds!", i));
            }
            int resIndex = currBitIndex / 8;

            boolean value = (block[blockIndex] & (1 << bitOffset)) != 0;
            res[resIndex] = (byte) (value
                    ? res[resIndex] | (1 << resOffset)
                    : res[resIndex] & ~(1 << resOffset));
            currBitIndex++;
        }

        return res;
    }

    public static byte[] permutation(byte[] block, int[] pBlock, boolean reversedOrder) {
        return permutation(block, pBlock, reversedOrder, true);
    }

    public static byte[] permutation(byte[] block, int[] pBlock) {
        return permutation(block, pBlock, false, true);
    }

    public static int leftCycleShift(int shift, int bits, int bitsCount) {
        int mask = (1 << bitsCount) - 1;
        return ((bits >>> (bitsCount - shift)) | ((bits & mask) << shift)) & mask;
    }

    public static byte[] xorBits(byte[] x, byte[] y) {
        if (x == null || y == null) {
            throw new NullPointerException("Blocks cannot be null!");
        }
        var size = Math.min(x.length, y.length);
        var res = new byte[size];
        for (int i = 0; i < size; i++) {
            res[i] = (byte) (x[i] ^ y[i]);
        }

        return res;
    }

    public static byte[] substitution(byte[] block) {
        if (block == null) {
            throw new NullPointerException("Block cannot be null!");
        }
        if (block.length != 6) {
            throw new IllegalArgumentException(
                    String.format("Invalid block size (%d != 6)!", block.length)
            );
        }

        byte[] result = new byte[4];

        long tmpBlock = 0;
        for (var b : block) {
            tmpBlock = (b & 0xFF) | (tmpBlock << 8);
        }

        for (int i = 0; i < 8; i++) {
            int[] bitsArr = new int[6];
            int sixBits = (int) ((tmpBlock >> (6 * (8 - i - 1))) & 0xFF);
            for (int j = 0; j < 6; j++) {
                bitsArr[j] = (sixBits >> (5 - j)) & 1;
            }

            int row = (bitsArr[0] << 1) | bitsArr[5];
            int col = (bitsArr[1] << 3) | (bitsArr[2] << 2) | (bitsArr[3] << 1) | (bitsArr[4]);
            int value = S_BLOCKS[i][row][col];

            result[i / 2] |= (byte) ((i & 1) != 0 ? value : value << 4);
        }

        return result;
    }

    public static String bytesToHexString(byte[] bytes, String separator) {
        var builder = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            builder.append(String.format("%02X", bytes[i]));
            if (i != bytes.length - 1) {
                builder.append(separator);
            }
        }
        return builder.toString();
    }

    public static String bytesToHexString(byte[] bytes) {
        return bytesToHexString(bytes, "");
    }

    public static String bytesToBinaryString(byte[] bytes, String separator) {
        var builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            builder.append(
                    String.format("%8s", Integer.toBinaryString(bytes[i] & 0xFF))
                            .replace(' ', '0')
            );
            if (i != bytes.length - 1) {
                builder.append(separator);
            }
        }
        return builder.toString();
    }

    public static String bytesToBinaryString(byte[] bytes) {
        return bytesToBinaryString(bytes, "");
    }

}
