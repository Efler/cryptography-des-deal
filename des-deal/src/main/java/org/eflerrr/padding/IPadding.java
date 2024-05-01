package org.eflerrr.padding;

public interface IPadding {

    byte[] makePadding(byte[] block, int size);

    byte[] undoPadding(byte[] block);

}
