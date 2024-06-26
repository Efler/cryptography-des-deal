package org.eflerrr.encrypt.encryptor.impl;

import lombok.Getter;
import org.eflerrr.encrypt.conversion.IEncryptConversion;
import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.expandkey.IExpandKey;

import static org.eflerrr.utils.Utils.xorBits;

@SuppressWarnings("Duplicates")
public class FeistelNetworkEncryptor implements IEncryptor {

    protected final IEncryptConversion encryptConversion;
    protected final IExpandKey expandKey;
    protected byte[][] rKeys;
    protected int rounds;
    @Getter
    protected int blockLength = 32 / 8;

    public FeistelNetworkEncryptor(
            IEncryptConversion encryptConversion,
            IExpandKey expandKey,
            int rounds) {
        this.encryptConversion = encryptConversion;
        this.expandKey = expandKey;
        this.rounds = rounds;
    }

    @Override
    public IEncryptor setKey(byte[] key) {
        if (key == null) {
            throw new NullPointerException("Key cannot be null!");
        }
        this.rKeys = expandKey.expand(key);
        return this;
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

        byte[] decryptedBlock = new byte[block.length];
        System.arraycopy(left, 0, decryptedBlock, 0, half);
        System.arraycopy(right, 0, decryptedBlock, half, half);
        return decryptedBlock;
    }

}
