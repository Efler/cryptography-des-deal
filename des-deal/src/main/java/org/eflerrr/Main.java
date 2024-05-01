package org.eflerrr;

import lombok.extern.slf4j.Slf4j;
import org.eflerrr.encrypt.manager.EncryptorManager;
import org.eflerrr.encrypt.mode.EncryptModes;
import org.eflerrr.padding.Paddings;

import java.io.IOException;
import java.nio.file.Paths;

import static org.eflerrr.encrypt.manager.EncryptorManager.EncryptionAlgorithm.DEAL_256;
import static org.eflerrr.encrypt.manager.EncryptorManager.EncryptionAlgorithm.DES;
import static org.eflerrr.encrypt.mode.EncryptModes.Mode.RandomDelta;
import static org.eflerrr.padding.Paddings.PaddingType.ISO10126;
import static org.eflerrr.utils.Utils.generateIV;

@Slf4j
@SuppressWarnings("Duplicates")
public class Main {

    public static void main(String[] args) {

        //----------------------------

        // configs ##############################|
        // key = 133457788BBCDFF1
        var keyForDES = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };
        // key = 133457788BBCDFF11255F9E7911355BD
        var keyForDEAL128 = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1,
                (byte) 0x12, (byte) 0x55, (byte) 0xF9, (byte) 0xE7,
                (byte) 0x91, (byte) 0x13, (byte) 0x55, (byte) 0xBD
        };
        // key = 133457788BBCDFF11255F9E7911355BD802F17DAAAC805CC
        var keyForDEAL192 = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1,
                (byte) 0x12, (byte) 0x55, (byte) 0xF9, (byte) 0xE7,
                (byte) 0x91, (byte) 0x13, (byte) 0x55, (byte) 0xBD,
                (byte) 0x80, (byte) 0x2F, (byte) 0x17, (byte) 0xDA,
                (byte) 0xAA, (byte) 0xC8, (byte) 0x05, (byte) 0xCC
        };
        // key = 133457788BBCDFF11255F9E7911355BD802F17DAAAC805CCFFEDCBA72233DDC0
        var keyForDEAL256 = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1,
                (byte) 0x12, (byte) 0x55, (byte) 0xF9, (byte) 0xE7,
                (byte) 0x91, (byte) 0x13, (byte) 0x55, (byte) 0xBD,
                (byte) 0x80, (byte) 0x2F, (byte) 0x17, (byte) 0xDA,
                (byte) 0xAA, (byte) 0xC8, (byte) 0x05, (byte) 0xCC,
                (byte) 0xFF, (byte) 0xED, (byte) 0xCB, (byte) 0xA7,
                (byte) 0x22, (byte) 0x33, (byte) 0xDD, (byte) 0xC0
        };

        EncryptorManager.EncryptionAlgorithm algorithm = DEAL_256;
        EncryptModes.Mode mode = RandomDelta;
        Paddings.PaddingType type = ISO10126;
        int threads = 7;

        var inputFile = "deadinside.jpg";
        var folder = "image";
        // configs ##############################|

        var encryptedFile = inputFile.substring(0, inputFile.lastIndexOf('.'))
                + "_encrypted"
                + inputFile.substring(inputFile.lastIndexOf('.'));
        var decryptedFile = inputFile.substring(0, inputFile.lastIndexOf('.'))
                + "_decrypted"
                + inputFile.substring(inputFile.lastIndexOf('.'));

        var manager = new EncryptorManager(
                switch (algorithm) {
                    case DES -> keyForDES;
                    case DEAL_128 -> keyForDEAL128;
                    case DEAL_192 -> keyForDEAL192;
                    case DEAL_256 -> keyForDEAL256;
                },
                algorithm, mode, type, generateIV((algorithm.equals(DES) ? 64 : 128) / 8)
        );

        try {
            log.info("Algorithm: {}", algorithm);
            log.info("Mode: {}", mode);
            log.info("Type: {}", type);
            log.info("Threads: {}", threads);
            log.info("initial file: {}", inputFile);
            log.info("encrypting file...");
            manager.encryptFileAsync(
                    Paths.get("des-deal", "src", "main", "resources", folder, inputFile)
                            .toAbsolutePath().toString(),
                    Paths.get("des-deal", "src", "main", "resources", folder, encryptedFile)
                            .toAbsolutePath().toString(),
                    threads);
            log.info("encrypted: {}", encryptedFile);
        } catch (IOException e) {
            log.error("EncryptFileAsync Error! Message: {}", e.getMessage());
        }

        try {
            log.info("decrypting file...");
            manager.decryptFileAsync(
                    Paths.get("des-deal", "src", "main", "resources", folder, encryptedFile)
                            .toAbsolutePath().toString(),
                    Paths.get("des-deal", "src", "main", "resources", folder, decryptedFile)
                            .toAbsolutePath().toString(),
                    threads);
            log.info("decrypted: {}", decryptedFile);
        } catch (IOException e) {
            log.error("DecryptFileAsync Error! Message : {}", e.getMessage());
        }

        //----------------------------


        //----------------------------

        /*
        // keyForDES = 133457788BBCDFF1
        byte[] keyForDES = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };
        // keyForDEAL = 133457788BBCDFF11255F9E7911355BD
        var keyForDEAL = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1,
                (byte) 0x12, (byte) 0x55, (byte) 0xF9, (byte) 0xE7,
                (byte) 0x91, (byte) 0x13, (byte) 0x55, (byte) 0xBD
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

        // keyForDES = 133457788BBCDFF1
        byte[] keyForDES = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };
        // keyForDEAL = 133457788BBCDFF11255F9E7911355BD
        var keyForDEAL = new byte[]{
                (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
                (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1,
                (byte) 0x12, (byte) 0x55, (byte) 0xF9, (byte) 0xE7,
                (byte) 0x91, (byte) 0x13, (byte) 0x55, (byte) 0xBD
        };

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        var manager = new EncryptorManager(
                keyForDEAL, DEAL_128, ECB, ZEROZ, new byte[128 / 8]
        );

        var encryptedMessage = manager.encryptAsync(messageBytes, 5);
        log.info("##### Encrypted message #####\n" + new String(encryptedMessage, StandardCharsets.UTF_8));

        log.info("");

        var decryptedMessage = manager.decryptAsync(encryptedMessage, 5);
        log.info("##### Decrypted message #####\n" + new String(decryptedMessage, StandardCharsets.UTF_8));
        */

        //----------------------------

    }

}
