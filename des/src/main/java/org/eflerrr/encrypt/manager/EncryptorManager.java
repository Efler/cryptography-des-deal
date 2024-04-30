package org.eflerrr.encrypt.manager;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;
import org.eflerrr.encrypt.mode.EncryptModes;
import org.eflerrr.padding.IPadding;
import org.eflerrr.padding.Paddings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.lang.System.arraycopy;
import static org.eflerrr.encrypt.mode.EncryptModes.getMode;
import static org.eflerrr.padding.Paddings.getPadding;

public class EncryptorManager {

    protected final AEncryptMode kernelMode;
    protected final IPadding padding;
    protected final int blockLength;

    public EncryptorManager(
            byte[] key,
            IEncryptor encryptor,
            EncryptModes.Mode mode,
            Paddings.PaddingType type,
            byte[] InitializationVector) {
        kernelMode = getMode(mode, encryptor.setKey(key), InitializationVector);
        padding = getPadding(type);
        blockLength = encryptor.getBlockLength();
    }

    public byte[] encryptSync(byte[] plain) {
        var withPadding = padding.makePadding(plain, blockLength);
        return kernelMode.encrypt(withPadding);
    }

    public byte[] decryptSync(byte[] encoded) {
        return padding.undoPadding(kernelMode.decrypt(encoded));
    }

    public byte[] encryptAsync(byte[] plain, int threadCount) {
        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
            byte[] result = new byte[(plain.length / blockLength + 1) * blockLength];
            List<CompletableFuture<Void>> futures = new ArrayList<>();

            int blocksPerThread = 1;
            while (blocksPerThread * threadCount < (plain.length + blockLength - 1) / blockLength) {
                blocksPerThread++;
            }
            int batch = blockLength * blocksPerThread;
            int parts = (plain.length + batch - 1) / batch;
            for (int i = 0; i < parts; i++) {
                int finalI = i;
                futures.add(
                        CompletableFuture.runAsync(() -> {
                            int start = finalI * batch;
                            int end = Math.min((finalI + 1) * batch, plain.length);
                            var bytes = new byte[end - start];
                            arraycopy(plain, start, bytes, 0, end - start);
                            if (finalI == parts - 1) {
                                bytes = padding.makePadding(bytes, blockLength);
                            }
                            var encrypted = kernelMode.encrypt(bytes);
                            arraycopy(encrypted, 0, result, start, encrypted.length);
                        }, executor)
                );
            }
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            executor.shutdown();
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }

            return result;

        } catch (InterruptedException e) {
            throw new RuntimeException("Executor was interrupted, Message: " + e);
        }
    }

    public byte[] decryptAsync(byte[] encoded, int threadCount) {
        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
            byte[] result = new byte[encoded.length];
            List<CompletableFuture<Void>> futures = new ArrayList<>();

            int blocksPerThread = 1;
            while (blocksPerThread * threadCount < encoded.length / blockLength) {
                blocksPerThread++;
            }
            int batch = blockLength * blocksPerThread;
            int parts = (encoded.length + batch - 1) / batch;
            for (int i = 0; i < parts; i++) {
                int finalI = i;
                futures.add(
                        CompletableFuture.runAsync(() -> {
                            int start = finalI * batch;
                            int end = Math.min((finalI + 1) * batch, encoded.length);
                            var bytes = new byte[end - start];
                            arraycopy(encoded, start, bytes, 0, end - start);
                            var decrypted = kernelMode.decrypt(bytes);
                            arraycopy(decrypted, 0, result, start, decrypted.length);
                        }, executor)
                );
            }
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            executor.shutdown();
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }

            return padding.undoPadding(result);

        } catch (InterruptedException e) {
            throw new RuntimeException("Executor was interrupted, Message: " + e);
        }
    }

    public void encryptFileSync(String inputFile, String outputFile) throws IOException {
        var data = Files.readAllBytes(Paths.get(inputFile));
        var encrypted = encryptSync(data);
        Files.write(Paths.get(outputFile), encrypted);
    }

    public void decryptFileSync(String inputFile, String outputFile) throws IOException {
        var data = Files.readAllBytes(Paths.get(inputFile));
        var decrypted = decryptSync(data);
        Files.write(Paths.get(outputFile), decrypted);
    }

    public void encryptFileAsync(String inputFile, String outputFile, int threadCount) throws IOException {
        var data = Files.readAllBytes(Paths.get(inputFile));
        var encrypted = encryptAsync(data, threadCount);
        Files.write(Paths.get(outputFile), encrypted);
    }

    public void decryptFileAsync(String inputFile, String outputFile, int threadCount) throws IOException {
        var data = Files.readAllBytes(Paths.get(inputFile));
        var decrypted = decryptAsync(data, threadCount);
        Files.write(Paths.get(outputFile), decrypted);
    }

}
