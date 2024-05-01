package org.eflerrr.encrypt.encryptor.impl;

import org.eflerrr.encrypt.conversion.impl.DEALEncryptConversion;
import org.eflerrr.expandkey.impl.DEALExpandKey;

import static java.lang.System.arraycopy;
import static org.eflerrr.utils.Utils.xorBits;

@SuppressWarnings("Duplicates")
public class DEALEncryptor extends FeistelNetworkEncryptor {

    public enum KeyType {
        KEY_SIZE_128,
        KEY_SIZE_192,
        KEY_SIZE_256
    }

    public DEALEncryptor(KeyType type) {
        super(new DEALEncryptConversion(), new DEALExpandKey(type),
                switch (type) {
                    case KEY_SIZE_128, KEY_SIZE_192 -> 6;
                    case KEY_SIZE_256 -> 8;
                });
        blockLength = 128 / 8;
    }

    @Override
    public byte[] encrypt(byte[] block) {
        if (rKeys == null) {
            throw new NullPointerException("Round keys are not configured!");
        }

        var half = block.length / 2;
        var left = new byte[half];
        var right = new byte[half];
        arraycopy(block, 0, left, 0, half);
        arraycopy(block, half, right, 0, half);

        for (int i = 0; i < rounds; i++) {
            byte[] tmp = xorBits(right, encryptConversion.encode(left, rKeys[i]));
            right = left;
            left = tmp;
        }

        byte[] encryptedBlock = new byte[block.length];
        arraycopy(left, 0, encryptedBlock, 0, half);
        arraycopy(right, 0, encryptedBlock, half, half);
        return encryptedBlock;
    }

    @Override
    public byte[] decrypt(byte[] block) {
        if (rKeys == null) {
            throw new NullPointerException("Round keys are not configured!");
        }

        var half = block.length / 2;
        var left = new byte[half];
        var right = new byte[half];
        arraycopy(block, 0, left, 0, half);
        arraycopy(block, half, right, 0, half);

        for (int i = rounds - 1; i >= 0; i--) {
            byte[] tmp = xorBits(left, encryptConversion.encode(right, rKeys[i]));
            left = right;
            right = tmp;
        }

        byte[] decryptedBlock = new byte[block.length];
        arraycopy(left, 0, decryptedBlock, 0, half);
        arraycopy(right, 0, decryptedBlock, half, half);
        return decryptedBlock;
    }

}
