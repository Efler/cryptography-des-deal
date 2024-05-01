package org.eflerrr.encrypt.conversion.impl;

import org.eflerrr.encrypt.conversion.IEncryptConversion;

import static org.eflerrr.config.des.DESEncryptConversionConfig.P_BLOCK_EXPAND;
import static org.eflerrr.config.des.DESEncryptConversionConfig.P_BLOCK_PLAIN;
import static org.eflerrr.utils.Utils.*;

public class DESEncryptConversion implements IEncryptConversion {

    @Override
    public byte[] encode(byte[] block, byte[] rKey) {
        byte[] result;
        result = permutation(block, P_BLOCK_EXPAND);
        result = xorBits(result, rKey);
        result = substitution(result);
        result = permutation(result, P_BLOCK_PLAIN);

        return result;
    }

}
