package org.eflerrr.encrypt.manager;

import org.eflerrr.encrypt.encryptor.IEncryptor;
import org.eflerrr.encrypt.mode.AEncryptMode;
import org.eflerrr.encrypt.mode.EncryptModes;
import org.eflerrr.padding.IPadding;
import org.eflerrr.padding.Paddings;

import static org.eflerrr.encrypt.mode.EncryptModes.getMode;
import static org.eflerrr.padding.Paddings.getPadding;

public class EncryptorManager {

    private final AEncryptMode kernelMode;
    private final IPadding padding;
    private final int blockLength;

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

    public byte[] encrypt(byte[] plain) {
        var withPadding = padding.makePadding(plain, blockLength);
        return kernelMode.encrypt(withPadding);
    }

    public byte[] decrypt(byte[] encoded) {
        return padding.undoPadding(kernelMode.decrypt(encoded));
    }

    // todo!

}
