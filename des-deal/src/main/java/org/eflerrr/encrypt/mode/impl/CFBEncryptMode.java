package org.eflerrr.encrypt.mode.impl;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;

import static org.eflerrr.utils.Utils.xorBits;

public class CFBEncryptMode extends AEncryptMode {

    public CFBEncryptMode(IEncryptor encryptor, int lengthBlock, byte[] IV) {
        super(encryptor, lengthBlock, IV);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        byte[] result = new byte[data.length];
        byte[] prev = IV;
        for (int i = 0; i < data.length / lengthBlock; ++i) {
            int offset = i * lengthBlock;
            byte[] block = new byte[lengthBlock];
            System.arraycopy(data, offset, block, 0, lengthBlock);
            byte[] encryptedBlock = xorBits(block, encryptor.encrypt(prev));
            System.arraycopy(encryptedBlock, 0, result, offset, encryptedBlock.length);
            prev = encryptedBlock;
        }
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        byte[] result = new byte[data.length];
        byte[] prev = IV;
        for (int i = 0; i < data.length / lengthBlock; ++i) {
            int offset = i * lengthBlock;
            byte[] block = new byte[lengthBlock];
            byte[] tmp = new byte[lengthBlock];
            System.arraycopy(data, offset, block, 0, lengthBlock);
            System.arraycopy(data, offset, tmp, 0, lengthBlock);
            byte[] decryptedBlock = xorBits(block, encryptor.encrypt(prev));
            System.arraycopy(decryptedBlock, 0, result, offset, decryptedBlock.length);
            prev = tmp;
        }
        return result;
    }

}
