package org.eflerrr.encrypt.encryptor.impl;

import org.eflerrr.encrypt.conversion.impl.DESEncryptConversion;
import org.eflerrr.expandkey.impl.DESExpandKey;

import static org.eflerrr.config.des.DESEncryptorConfig.FINAL_PERMUTATION;
import static org.eflerrr.config.des.DESEncryptorConfig.INITIAL_PERMUTATION;
import static org.eflerrr.utils.Utils.permutation;

public class DESEncryptor extends FeistelNetworkEncryptor {

    public DESEncryptor() {
        super(new DESEncryptConversion(), new DESExpandKey(), 16);
        blockLength = 64 / 8;
    }

    @Override
    public byte[] encrypt(byte[] block) {
        var initialPermutedBlock = permutation(block, INITIAL_PERMUTATION);
        var encryptedBlock = super.encrypt(initialPermutedBlock);
        return permutation(encryptedBlock, FINAL_PERMUTATION);
    }

    @Override
    public byte[] decrypt(byte[] block) {
        var initialPermutedBlock = permutation(block, INITIAL_PERMUTATION);
        var encryptedBlock = super.decrypt(initialPermutedBlock);
        return permutation(encryptedBlock, FINAL_PERMUTATION);
    }

}
