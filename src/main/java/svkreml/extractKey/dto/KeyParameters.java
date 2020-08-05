package svkreml.extractKey.dto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class KeyParameters {

   public DERBitString attributes;
    public AlgorithmIdentifier algorithm;

    public KeyParameters(ASN1Sequence seq) {
        for (ASN1Encodable tagObj : seq) {
            if (tagObj instanceof DERBitString) {
                attributes = DERBitString.getInstance(tagObj);
            }
            if (tagObj instanceof ASN1TaggedObject) {
                if (((ASN1TaggedObject) tagObj).getTagNo() == 0) {
                    algorithm = AlgorithmIdentifier.getInstance((ASN1TaggedObject) tagObj, false);
                }
            }
        }
    }

    public KeyParameters(AlgorithmIdentifier algorithm, DERBitString attributes) {
        this.attributes = attributes;
        this.algorithm = algorithm;
    }

    public static KeyParameters getInstance(ASN1Sequence seq) {
        return new KeyParameters(seq);
    }

    @Override
    public String toString() {
        return "KeyParameters{" +
                "attributes=" + attributes +
                ", algorithm=" + algorithm +
                '}';
    }
}
