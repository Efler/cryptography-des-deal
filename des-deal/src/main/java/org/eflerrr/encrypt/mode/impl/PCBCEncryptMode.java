package org.eflerrr.encrypt.mode.impl;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;

import static org.eflerrr.utils.Utils.xorBits;

@SuppressWarnings("Duplicates")
public class PCBCEncryptMode extends AEncryptMode {

    public PCBCEncryptMode(IEncryptor encryptor, int lengthBlock, byte[] IV) {
        super(encryptor, lengthBlock, IV);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        byte[] result = new byte[data.length];
        byte[] xorBlock = IV;
        for (int i = 0; i < data.length / lengthBlock; ++i) {
            int offset = i * lengthBlock;
            byte[] block = new byte[lengthBlock];
            System.arraycopy(data, offset, block, 0, lengthBlock);
            byte[] encryptedBlock = encryptor.encrypt(xorBits(block, xorBlock));
            System.arraycopy(encryptedBlock, 0, result, offset, encryptedBlock.length);
            xorBlock = xorBits(encryptedBlock, block);
        }
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        byte[] result = new byte[data.length];
        byte[] xorBlock = IV;
        for (int i = 0; i < data.length / lengthBlock; ++i) {
            int offset = i * lengthBlock;
            byte[] block = new byte[lengthBlock];
            System.arraycopy(data, offset, block, 0, lengthBlock);
            byte[] decryptedBlock = xorBits(encryptor.decrypt(block), xorBlock);
            System.arraycopy(decryptedBlock, 0, result, offset, decryptedBlock.length);
            xorBlock = xorBits(decryptedBlock, block);
        }
        return result;
    }

}
