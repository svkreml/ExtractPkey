package svkreml.extractKey.dto;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.util.encoders.Hex;

public class Primary {
    byte[] key;

    public Primary(byte[] primary) {
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(primary);
        if (asn1Sequence.size() != 1) throw new RuntimeException("Primary should have 1 element");
        key = BEROctetString.getInstance(asn1Sequence.getObjectAt(0)).getOctets();
    }

    public static Primary getInstance(byte[] primary) {
        return new Primary(primary);
    }

    @Override
    public String toString() {
        return "Primary{" +
                "key=" + Hex.toHexString(key) +
                '}';
    }
}
