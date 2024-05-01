package org.eflerrr.expandkey.impl;

import org.eflerrr.encrypt.encryptor.impl.DEALEncryptor;
import org.eflerrr.encrypt.encryptor.impl.DESEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;
import org.eflerrr.encrypt.mode.impl.CBCEncryptMode;
import org.eflerrr.expandkey.IExpandKey;

import static java.lang.System.arraycopy;
import static org.eflerrr.config.deal.DEALExpandKeyConfig.FIXED_DES_KEY;
import static org.eflerrr.utils.Utils.xorBits;

public class DEALExpandKey implements IExpandKey {

    private final AEncryptMode DESModeCBC;
    private final int rounds;
    private final int s;

    public DEALExpandKey(DEALEncryptor.KeyType type) {
        var DES = new DESEncryptor();
        DES.setKey(FIXED_DES_KEY);
        this.DESModeCBC = new CBCEncryptMode(DES, DES.getBlockLength(), new byte[64 / 8]);
        switch (type) {
            case KEY_SIZE_128 -> {
                this.rounds = 6;
                this.s = 2;
            }
            case KEY_SIZE_192 -> {
                this.rounds = 6;
                this.s = 3;
            }
            default -> {
                this.rounds = 8;
                this.s = 4;
            }
        }
    }

    @Override
    public byte[][] expand(byte[] key) {
        byte[][] keys = new byte[rounds][];
        byte[][] keysDES = new byte[s][];

        for (int i = 0; i < s; i++) {
            byte[] initKey = new byte[8];
            arraycopy(key, 8 * i, initKey, 0, initKey.length);
            keysDES[i] = initKey;
        }

        keys[0] = DESModeCBC.encrypt(keysDES[0]);
        for (int i = 1; i < s; i++) {
            keys[i] = DESModeCBC.encrypt(xorBits(keysDES[i], keys[i - 1]));
        }
        var constantNumber = 0;
        for (int i = s; i < rounds; i++) {
            long constant = 1L << (64 - (1 << constantNumber));
            byte[] constantBytes = new byte[8];
            for (int j = 0; j < 8; j++) {
                constantBytes[j] = (byte) ((constant >>> ((7 - j) * 8)) & 0xFF);
            }
            keys[i] = DESModeCBC.encrypt(xorBits(xorBits(keysDES[i % s], constantBytes), keys[i - 1]));
        }

        return keys;
    }
}
