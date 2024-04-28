package org.eflerrr.padding;

import org.eflerrr.padding.impl.ANSIX923Padding;
import org.eflerrr.padding.impl.ISO10126Padding;
import org.eflerrr.padding.impl.PKCS7Padding;
import org.eflerrr.padding.impl.ZerozPadding;

public class Paddings {

    public enum PaddingType {
        ZEROZ, ANSIX923, ISO10126, PKCS7
    }

    public static IPadding getPadding(PaddingType type) {
        return switch (type) {
            case ZEROZ -> new ZerozPadding();
            case ANSIX923 -> new ANSIX923Padding();
            case ISO10126 -> new ISO10126Padding();
            case PKCS7 -> new PKCS7Padding();
        };
    }

}
