package org.eflerrr.encrypt.mode;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.eflerrr.encrypt.encryptor.IEncryptor;

@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class AEncryptMode {

    protected final IEncryptor encryptor;
    protected final int lengthBlock;
    protected final byte[] IV;

    public abstract byte[] encrypt(byte[] data);
    public abstract byte[] decrypt(byte[] data);

}
