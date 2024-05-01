package org.eflerrr.encrypt.conversion;

public interface IEncryptConversion {

    byte[] encode(byte[] block, byte[] rKey);

}
