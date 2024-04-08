package org.eflerrr.encrypt.encryptor.impl;

import org.eflerrr.encrypt.conversion.IEncryptConversion;
import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.expandkey.IExpandKey;

import static org.eflerrr.utils.Utils.xorBits;

@SuppressWarnings("Duplicates")
public class FeistelNetworkEncryptor implements IEncryptor {

    private final IEncryptConversion encryptConversion;
    private final IExpandKey expandKey;
    private byte[][] rKeys;
    protected int rounds;

    public FeistelNetworkEncryptor(
            IEncryptConversion encryptConversion,
            IExpandKey expandKey,
            int rounds) {
        this.encryptConversion = encryptConversion;
        this.expandKey = expandKey;
        this.rounds = rounds;
    }

    @Override
    public void setKey(byte[] key) {
        if (key == null) {
            throw new NullPointerException("Key cannot be null!");
        }
        this.rKeys = expandKey.expand(key);
    }

    @Override
    public byte[] encrypt(byte[] block) {
        if (rKeys == null) {
            throw new NullPointerException("Round keys are not configured!");
        }

        var half = block.length / 2;
        var left = new byte[half];
        var right = new byte[half];
        System.arraycopy(block, 0, left, 0, half);
        System.arraycopy(block, half, right, 0, half);

        for (int i = 0; i < rounds - 1; i++) {
            var tmp = xorBits(left, encryptConversion.encode(right, rKeys[i]));
            left = right;
            right = tmp;
        }
        left = xorBits(left, encryptConversion.encode(right, rKeys[rounds - 1]));

        byte[] encryptedBlock = new byte[block.length];
        System.arraycopy(left, 0, encryptedBlock, 0, half);
        System.arraycopy(right, 0, encryptedBlock, half, half);
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
        System.arraycopy(block, 0, left, 0, half);
        System.arraycopy(block, half, right, 0, half);

        left = xorBits(left, encryptConversion.encode(right, rKeys[rounds - 1]));
        for (int i = rounds - 2; i >= 0; --i) {
            byte[] tmp = xorBits(right, encryptConversion.encode(left, rKeys[i]));
            right = left;
            left = tmp;
        }

        byte[] encryptedBlock = new byte[block.length];
        System.arraycopy(left, 0, encryptedBlock, 0, half);
        System.arraycopy(right, 0, encryptedBlock, half, half);
        return encryptedBlock;
    }

}
