package svkreml.extractKey.dto;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.lang.reflect.Array;

public class Mask {
    byte[] key;
    byte[] salt;
    byte[] hMacKey;

    public Mask(byte[] mask) {
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(mask);
        if (asn1Sequence.size() != 3) throw new RuntimeException("Mask should have 3 elements");
        key = Arrays.reverse( BEROctetString.getInstance(asn1Sequence.getObjectAt(0)).getOctets());
        salt = BEROctetString.getInstance(asn1Sequence.getObjectAt(1)).getOctets();
        hMacKey = BEROctetString.getInstance(asn1Sequence.getObjectAt(2)).getOctets();

        if (key == null || salt == null || hMacKey == null)
            throw new RuntimeException("Ошибка в данных masks.key.");
    }

    public static Mask getInstance(byte[] mask) {
        return new Mask(mask);
    }


    @Override
    public String toString() {
        return "Mask{" +
                "key=" + Hex.toHexString(key) +
                ", salt=" + Hex.toHexString(salt) +
                ", hMacKey=" + Hex.toHexString(hMacKey) +
                '}';
    }
}
