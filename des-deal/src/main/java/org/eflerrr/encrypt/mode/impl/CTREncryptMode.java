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
        byte[] counterInBytes = new byte[lengthHalf];
        for (int j = 0; j < counterInBytes.length; ++j) {
            counterInBytes[j] = (byte) (i >> ((lengthHalf - 1) - j) * 8);
        }
        System.arraycopy(counterInBytes, 0, processBlock, lengthHalf, lengthHalf);
        byte[] processedBlock = xorBits(block, encryptor.encrypt(processBlock));
        System.arraycopy(processedBlock, 0, output, offset, processedBlock.length);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        try (var executor = Executors.newFixedThreadPool(
                Runtime.getRuntime().availableProcessors() - 1)) {
            byte[] result = new byte[data.length];
            List<CompletableFuture<Void>> futures = new ArrayList<>();
            for (int i = 0; i < data.length / lengthBlock; i++) {
                int finalI = i;
                futures.add(
                        CompletableFuture.runAsync(
                                () -> process(data, result, finalI), executor
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

    @Override
    public byte[] decrypt(byte[] data) {
        return encrypt(data);
    }

}
