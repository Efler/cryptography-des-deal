package org.eflerrr.encrypt.mode.impl;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.eflerrr.utils.Utils.xorBits;

@SuppressWarnings("Duplicates")
public class CBCEncryptMode extends AEncryptMode {

    public CBCEncryptMode(IEncryptor encryptor, int lengthBlock, byte[] IV) {
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
            byte[] encryptedBlock = encryptor.encrypt(xorBits(block, prev));
            System.arraycopy(encryptedBlock, 0, result, offset, encryptedBlock.length);
            prev = encryptedBlock;
        }
        return result;
    }

    private void decryptProcess(byte[] input, byte[] output, int i) {
        byte[] prev = new byte[lengthBlock];
        if (i == 0) {
            prev = IV;
        } else {
            System.arraycopy(
                    input, (i - 1) * lengthBlock,
                    prev, 0,
                    lengthBlock
            );
        }
        int offset = i * lengthBlock;
        byte[] block = new byte[lengthBlock];
        System.arraycopy(input, offset, block, 0, lengthBlock);
        byte[] decryptedBlock = xorBits(prev, encryptor.decrypt(block));
        System.arraycopy(decryptedBlock, 0, output, offset, decryptedBlock.length);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        try (var executor = Executors.newFixedThreadPool(
                Runtime.getRuntime().availableProcessors() - 1)) {
            byte[] result = new byte[data.length];
            List<CompletableFuture<Void>> futures = new ArrayList<>();
            for (int i = 0; i < data.length / lengthBlock; i++) {
                int finalI = i;
                futures.add(
                        CompletableFuture.runAsync(
                                () -> decryptProcess(data, result, finalI), executor
                        ));
            }
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            executor.shutdown();
            try {
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
                return result;
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
                return result;
            }
        }
    }

}
