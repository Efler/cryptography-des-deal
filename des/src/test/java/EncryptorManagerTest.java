import lombok.extern.slf4j.Slf4j;
import org.eflerrr.encrypt.encryptor.impl.DESEncryptor;
import org.eflerrr.encrypt.manager.EncryptorManager;
import org.eflerrr.encrypt.mode.EncryptModes;
import org.eflerrr.padding.Paddings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.eflerrr.utils.Utils.bytesToHexString;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@SuppressWarnings("all")
public class EncryptorManagerTest {

    private final String INITIAL_PATH;
    private final String ENCRYPTED_PATH;
    private final String DECRYPTED_PATH;

    public EncryptorManagerTest() throws URISyntaxException {
        INITIAL_PATH = Paths.get("src", "test", "resources", "initial.txt")
                .toAbsolutePath().toString();
        ENCRYPTED_PATH = Paths.get("src", "test", "resources", "encrypted.txt")
                .toAbsolutePath().toString();
        DECRYPTED_PATH = Paths.get("src", "test", "resources", "decrypted.txt")
                .toAbsolutePath().toString();
    }

    @BeforeEach
    public void logsToSeparate() {
        log.trace("--------------------------------------------------");
    }

    @AfterEach
    public void finalSeparate() {
        log.trace("--------------------------------------------------");
        log.trace("");
    }

    // key = 133457788BBCDFF1
    public static final byte[] KEY = new byte[]{
            (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
    };

    // plain text (exact length) = 0123456789ABCDEF
    public static final byte[] PLAIN_TEXT_EXACT_LENGTH = new byte[]{
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
    };
    // plain text (wrong length) = 0123456789ABCDEFAE2D
    public static final byte[] PLAIN_TEXT_WRONG_LENGTH = new byte[]{
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0xAE, (byte) 0x2D
    };

    // initialization vector = 1F3400789AB5DEF7
    private static final byte[] IV = new byte[]{
            (byte) 0x1F, (byte) 0x34, (byte) 0x00, (byte) 0x78,
            (byte) 0x9A, (byte) 0xB5, (byte) 0xDE, (byte) 0xF7
    };

    // ------------------------------

    private static Stream<Arguments> provideTestData() {
        return Stream.of(EncryptModes.Mode.values())
                .flatMap(mode -> Stream.of(Paddings.PaddingType.values())
                        .map(type -> Arguments.of(mode, type)));
    }

    private static Stream<Arguments> provideFileTestData() {
        return Stream.of(EncryptModes.Mode.values())
                .flatMap(mode -> Stream.of(Paddings.PaddingType.values())
                        .flatMap(type -> IntStream.range(1, 8)
                                .mapToObj(threads -> Arguments.of(mode, type, threads))));
    }

    @ParameterizedTest
    @MethodSource("provideTestData")
    public void encryptSyncBlockExactLengthTest(EncryptModes.Mode mode, Paddings.PaddingType type) {
        EncryptorManager manager = new EncryptorManager(KEY, new DESEncryptor(), mode, type, IV);
        log.info("Mode: {}", mode);
        log.info("Padding: {}", type);
        log.info("Plain text:  hex -> {} ", bytesToHexString(PLAIN_TEXT_EXACT_LENGTH));
        byte[] encrypted = manager.encryptSync(PLAIN_TEXT_EXACT_LENGTH);
        log.info("Encrypted:  hex -> {} ", bytesToHexString(encrypted));
        byte[] decrypted = manager.decryptSync(encrypted);
        log.info("Decrypted:  hex -> {} ", bytesToHexString(decrypted));
        assertArrayEquals(PLAIN_TEXT_EXACT_LENGTH, decrypted);
    }

    @ParameterizedTest
    @MethodSource("provideTestData")
    public void encryptSyncBlockWrongLengthTest(EncryptModes.Mode mode, Paddings.PaddingType type) {
        EncryptorManager manager = new EncryptorManager(KEY, new DESEncryptor(), mode, type, IV);
        log.info("Mode: {}", mode);
        log.info("Padding: {}", type);
        log.info("Plain text:  hex -> {} ", bytesToHexString(PLAIN_TEXT_WRONG_LENGTH));
        byte[] encrypted = manager.encryptSync(PLAIN_TEXT_WRONG_LENGTH);
        log.info("Encrypted:  hex -> {} ", bytesToHexString(encrypted));
        byte[] decrypted = manager.decryptSync(encrypted);
        log.info("Decrypted:  hex -> {} ", bytesToHexString(decrypted));
        assertArrayEquals(PLAIN_TEXT_WRONG_LENGTH, decrypted);
    }

    @ParameterizedTest
    @MethodSource("provideFileTestData")
    public void encryptAsyncTextMessageFromFileTest(
            EncryptModes.Mode mode, Paddings.PaddingType type, int threads
    ) throws IOException {
        EncryptorManager manager = new EncryptorManager(KEY, new DESEncryptor(), mode, type, IV);
        log.info("--- ENCRYPTING TEXT MESSAGE FROM FILE ---");
        log.info("Mode: {}", mode);
        log.info("Padding: {}", type);
        log.info("Threads: {}", threads);

        try {

            log.info("Initial file: {}", INITIAL_PATH);
            manager.encryptFileAsync(INITIAL_PATH, ENCRYPTED_PATH, threads);
            log.info("Encrypted file: {}", ENCRYPTED_PATH);
            manager.decryptFileAsync(ENCRYPTED_PATH, DECRYPTED_PATH, threads);
            log.info("Decrypted file: {}", DECRYPTED_PATH);

            assertEquals(
                    new String(Files.readAllBytes(Paths.get(INITIAL_PATH)), StandardCharsets.UTF_8),
                    new String(Files.readAllBytes(Paths.get(DECRYPTED_PATH)), StandardCharsets.UTF_8)
            );

        } catch (IOException e) {
            log.error("Error while encrypting file test: {}", e.getMessage());
            fail();
        }
    }

}
