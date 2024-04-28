package org.eflerrr.encrypt.mode;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.impl.*;

public class EncryptModes {

    public enum Mode {
        ECB,
        CBC, PCBC,
        CFB, OFB,
        CTR, RandomDelta
    }

    public static AEncryptMode getMode(
            Mode mode,
            IEncryptor encryptor,
            byte[] InitializationVector) {
        int size = encryptor.getBlockLength();
        return switch (mode) {
            case ECB -> new ECBEncryptMode(encryptor, size, InitializationVector);
            case CBC -> new CBCEncryptMode(encryptor, size, InitializationVector);
            case PCBC -> new PCBCEncryptMode(encryptor, size, InitializationVector);
            case CFB -> new CFBEncryptMode(encryptor, size, InitializationVector);
            case OFB -> new OFBEncryptMode(encryptor, size, InitializationVector);
            case CTR -> new CTREncryptMode(encryptor, size, InitializationVector);
            case RandomDelta -> new RandomDeltaEncryptMode(encryptor, size, InitializationVector);
        };
    }
}
