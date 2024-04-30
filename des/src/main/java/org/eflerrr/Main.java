package org.eflerrr;

import lombok.extern.slf4j.Slf4j;
import org.eflerrr.encrypt.encryptor.impl.DESEncryptor;
import org.eflerrr.encrypt.manager.EncryptorManager;
import org.eflerrr.encrypt.mode.EncryptModes;
import org.eflerrr.padding.Paddings;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Paths;

import static org.eflerrr.encrypt.mode.EncryptModes.Mode.RandomDelta;
import static org.eflerrr.padding.Paddings.PaddingType.ISO10126;
import static org.eflerrr.utils.Utils.generateIV;

@Slf4j
@SuppressWarnings("Duplicates")
public class Main {

    public static void main(String[] args) throws URISyntaxException, IOException {

        //----------------------------

        // configs ##############################
        var key = new byte[]{                                           // key = 133457788BBCDFF1
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };

        EncryptModes.Mode mode = RandomDelta;
        Paddings.PaddingType type = ISO10126;
        int threads = 5;

        var inputFile = "message.txt";
        var encryptedFile = "message_encrypted.txt";
        var decryptedFile = "message_decrypted.txt";

        var folder = "text";
        // configs ##############################

        var manager = new EncryptorManager(
                key, new DESEncryptor(),
                mode, type, generateIV(64 / 8)
        );

        try {
            log.info("Mode: {}", mode);
            log.info("Type: {}", type);
            log.info("Threads: {}", threads);
            log.info("initial file: {}", inputFile);
            log.info("encrypting file...");
            manager.encryptFileAsync(
                    Paths.get("des", "src", "main", "resources", folder, inputFile)
                            .toAbsolutePath().toString(),
                    Paths.get("des", "src", "main", "resources", folder, encryptedFile)
                            .toAbsolutePath().toString(),
                    threads);
            log.info("encrypted: {}", encryptedFile);
        } catch (IOException e) {
            log.error("EncryptFileAsync Error! Message: {}", e.getMessage());
        }

        try {
            log.info("decrypting file...");
            manager.decryptFileAsync(
                    Paths.get("des", "src", "main", "resources", folder, encryptedFile)
                            .toAbsolutePath().toString(),
                    Paths.get("des", "src", "main", "resources", folder, decryptedFile)
                            .toAbsolutePath().toString(),
                    threads);
            log.info("decrypted: {}", decryptedFile);
        } catch (IOException e) {
            log.error("DecryptFileAsync Error! Message : {}", e.getMessage());
        }

        //----------------------------


        //----------------------------

        /*
        // key = 133457788BBCDFF1
        byte[] key = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };
        log.debug("[Key] hex: {}, binary: {}",
                bytesToHexString(key), bytesToBinaryString(key, "-"))
        ;

        // plain block = 0123456789ABCDEFAE2D
        // plain block = 0123456789ABCDEF
        byte[] plainBlock = new byte[]{
                (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
                (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
//                (byte) 0xAE, (byte) 0x2D
        };
        log.debug("[Plain block] hex: {}, binary: {}",
                bytesToHexString(plainBlock), bytesToBinaryString(plainBlock, "-")
        );


        var manager = new EncryptorManager(
                key, new DESEncryptor(), ECB, PKCS7, generateIV(64 / 8)
        );

        // encryptBlock should be 85E813540F0AB4055D4EF9F168F42416
        var encryptBlock = manager.encryptSync(plainBlock);
        log.debug("[Encrypted block] hex: {}, binary: {}",
                bytesToHexString(encryptBlock), bytesToBinaryString(encryptBlock, "-")
        );

        var decryptBlock = manager.decryptSync(encryptBlock);
        log.debug("[Decrypted block] hex: {}, binary: {}",
                bytesToHexString(decryptBlock), bytesToBinaryString(decryptBlock, "-")
        );
        */

        //----------------------------


        //----------------------------

        /*
        String message = """
                Hello, World!
                This is a test message.
                Adding more lines to the test message.
                This is line 4.
                This is line 5.
                This is line 6.
                This is line 7.
                This is line 8.
                This is line 9.
                This is line 10.
                :)
                """;

        byte[] key = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        var manager = new EncryptorManager(
                key, new DESEncryptor(), CTR, ISO10126, generateIV(64 / 8)
        );

        var encryptedMessage = manager.encryptAsync(messageBytes, 5);
        log.info("##### Encrypted message #####\n" + new String(encryptedMessage, StandardCharsets.UTF_8));

        log.info();

        var decryptedMessage = manager.decryptAsync(encryptedMessage, 5);
        log.info("##### Decrypted message #####\n" + new String(decryptedMessage, StandardCharsets.UTF_8));
        */

        //----------------------------

    }

}
