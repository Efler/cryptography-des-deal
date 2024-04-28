package org.eflerrr.encrypt.encryptor;

public interface IEncryptor {

    byte[] encrypt(byte[] block);

    byte[] decrypt(byte[] block);

    IEncryptor setKey(byte[] key);

    int getBlockLength();

}
