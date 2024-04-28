package org.eflerrr.encrypt.mode.impl;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;

import java.util.stream.IntStream;

public class ECBEncryptMode extends AEncryptMode {

    public ECBEncryptMode(IEncryptor encryptor, int lengthBlock, byte[] IV) {
        super(encryptor, lengthBlock, IV);
    }

    private void processEncrypt(byte[] input, byte[] output, int i) {
        int offset = i * lengthBlock;
        byte[] block = new byte[lengthBlock];
        System.arraycopy(input, offset, block, 0, lengthBlock);
        byte[] encryptedBlock = encryptor.encrypt(block);
        System.arraycopy(encryptedBlock, 0, output, offset, encryptedBlock.length);
    }

    private void processDecrypt(byte[] input, byte[] output, int i) {
        int offset = i * lengthBlock;
        byte[] block = new byte[lengthBlock];
        System.arraycopy(input, offset, block, 0, lengthBlock);
        byte[] decryptedBlock = encryptor.decrypt(block);
        System.arraycopy(decryptedBlock, 0, output, offset, decryptedBlock.length);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        byte[] result = new byte[data.length];
        IntStream.range(0, data.length / lengthBlock)
                .parallel()
                .forEach(i -> processEncrypt(data, result, i));
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        byte[] result = new byte[data.length];
        IntStream.range(0, data.length / lengthBlock)
                .parallel()
                .forEach(i -> processDecrypt(data, result, i));
        return result;
    }

}
