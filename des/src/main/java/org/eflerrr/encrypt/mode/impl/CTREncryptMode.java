package org.eflerrr.encrypt.mode.impl;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;

import java.util.stream.IntStream;

import static org.eflerrr.utils.Utils.xorBits;

public class CTREncryptMode extends AEncryptMode {

    public CTREncryptMode(IEncryptor encryptor, int lengthBlock, byte[] IV) {
        super(encryptor, lengthBlock, IV);
    }

    private void process(byte[] input, byte[] output, int i) {
        int offset = i * lengthBlock;
        byte[] block = new byte[lengthBlock];
        System.arraycopy(input, offset, block, 0, lengthBlock);
        byte[] processBlock = new byte[lengthBlock];
        int lengthHalf = lengthBlock / 2;
        System.arraycopy(IV, 0, processBlock, 0, lengthHalf);
        byte[] counterInBytes = new byte[Integer.BYTES];
        for (int j = 0; j < counterInBytes.length; ++j) {
            counterInBytes[j] = (byte) (i >> (3 - j) * 8);
        }
        System.arraycopy(counterInBytes, 0, processBlock, lengthHalf, lengthHalf);
        byte[] processedBlock = xorBits(block, encryptor.encrypt(processBlock));
        System.arraycopy(processedBlock, 0, output, offset, processedBlock.length);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        byte[] result = new byte[data.length];
        IntStream.range(0, data.length / lengthBlock)
                .parallel()
                .forEach(i -> process(data, result, i));
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return encrypt(data);
    }

}
