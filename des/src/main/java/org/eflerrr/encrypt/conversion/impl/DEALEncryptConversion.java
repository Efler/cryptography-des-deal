package org.eflerrr.encrypt.conversion.impl;

import org.eflerrr.encrypt.conversion.IEncryptConversion;
import org.eflerrr.encrypt.encryptor.impl.DESEncryptor;

public class DEALEncryptConversion implements IEncryptConversion {

    @Override
    public byte[] encode(byte[] block, byte[] rKey) {
        return new DESEncryptor()
                .setKey(rKey)
                .encrypt(block);
    }

}
