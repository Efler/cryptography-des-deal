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

import java.util.stream.Stream;

import static org.eflerrr.utils.Utils.bytesToHexString;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@Slf4j
@SuppressWarnings("all")
public class EncryptorManagerTest {

    @BeforeEach
    public void logsToSeparate() {
        log.trace("--------------------------------------------------");
    }

    @AfterEach
    public void finalSeparate() {
        log.trace("--------------------------------------------------");
        log.trace("");
    }

    // todo: key = 133457788BBCDFF1
    public static final byte[] KEY = new byte[]{
            (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
    };

    // todo: plain text (exact length) = 0123456789ABCDEF
    public static final byte[] PLAIN_TEXT_EXACT_LENGTH = new byte[]{
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
    };
    // todo: plain text (wrong length) = 0123456789ABCDEFAE2D
    public static final byte[] PLAIN_TEXT_WRONG_LENGTH = new byte[]{
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0xAE, (byte) 0x2D
    };

    // todo: initialization vector = 1F3400789AB5DEF7
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

    @ParameterizedTest
    @MethodSource("provideTestData")
    public void encryptBlockExactLengthTest(EncryptModes.Mode mode, Paddings.PaddingType type) {
        EncryptorManager manager = new EncryptorManager(KEY, new DESEncryptor(), mode, type, IV);
        log.info("Mode: {}", mode);
        log.info("Padding: {}", type);
        log.info("Plain text:  hex -> {} ", bytesToHexString(PLAIN_TEXT_EXACT_LENGTH));
        byte[] encrypted = manager.encrypt(PLAIN_TEXT_EXACT_LENGTH);
        log.info("Encrypted:  hex -> {} ", bytesToHexString(encrypted));
        byte[] decrypted = manager.decrypt(encrypted);
        log.info("Decrypted:  hex -> {} ", bytesToHexString(decrypted));
        assertArrayEquals(PLAIN_TEXT_EXACT_LENGTH, decrypted);
    }

    @ParameterizedTest
    @MethodSource("provideTestData")
    public void encryptBlockWrongLengthTest(EncryptModes.Mode mode, Paddings.PaddingType type) {
        EncryptorManager manager = new EncryptorManager(KEY, new DESEncryptor(), mode, type, IV);
        log.info("Mode: {}", mode);
        log.info("Padding: {}", type);
        log.info("Plain text:  hex -> {} ", bytesToHexString(PLAIN_TEXT_WRONG_LENGTH));
        byte[] encrypted = manager.encrypt(PLAIN_TEXT_WRONG_LENGTH);
        log.info("Encrypted:  hex -> {} ", bytesToHexString(encrypted));
        byte[] decrypted = manager.decrypt(encrypted);
        log.info("Decrypted:  hex -> {} ", bytesToHexString(decrypted));
        assertArrayEquals(PLAIN_TEXT_WRONG_LENGTH, decrypted);
    }

}
