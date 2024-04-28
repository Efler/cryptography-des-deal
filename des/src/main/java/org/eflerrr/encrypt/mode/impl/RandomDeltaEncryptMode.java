package org.eflerrr.encrypt.mode.impl;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.IntStream;

import static org.eflerrr.utils.Utils.xorBits;

@SuppressWarnings("Duplicates")
public class RandomDeltaEncryptMode extends AEncryptMode {

    public RandomDeltaEncryptMode(IEncryptor encryptor, int lengthBlock, byte[] IV) {
        super(encryptor, lengthBlock, IV);
    }

    private void processEncrypt(byte[] input, byte[] output, BigInteger delta, int i) {
        var init = new BigInteger(IV);
        var initCurr = init.add(delta.multiply(BigInteger.valueOf(i)));
        int offset = i * lengthBlock;
        byte[] block = new byte[lengthBlock];
        System.arraycopy(input, offset, block, 0, lengthBlock);
        byte[] encryptedBlock = encryptor.encrypt(xorBits(initCurr.toByteArray(), block));
        System.arraycopy(encryptedBlock, 0, output, offset, encryptedBlock.length);
    }

    private void processDecrypt(byte[] input, byte[] output, BigInteger delta, int i) {
        var init = new BigInteger(IV);
        var initCurr = init.add(delta.multiply(BigInteger.valueOf(i)));
        int offset = i * lengthBlock;
        byte[] block = new byte[lengthBlock];
        System.arraycopy(input, offset, block, 0, lengthBlock);
        byte[] decryptedBlock = xorBits(encryptor.decrypt(block), initCurr.toByteArray());
        System.arraycopy(decryptedBlock, 0, output, offset, decryptedBlock.length);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        byte[] result = new byte[data.length];
        IntStream.range(0, data.length / lengthBlock)
                .parallel()
                .forEach(i -> processEncrypt(
                        data, result,
                        new BigInteger(Arrays.copyOf(IV, lengthBlock / 2)),
                        i));
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        byte[] result = new byte[data.length];
        IntStream.range(0, data.length / lengthBlock)
                .parallel()
                .forEach(i -> processDecrypt(
                        data, result,
                        new BigInteger(Arrays.copyOf(IV, lengthBlock / 2)),
                        i));
        return result;
    }

}
