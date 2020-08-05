package svkreml.extractKey.dto;

import org.bouncycastle.asn1.*;
import svkreml.extractKey.X509Reader;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Header {
    public byte[] hMACKey;
    public byte[] publicX;
    public X509Certificate certificate;
    public X509Certificate certificate2;
    public DERBitString attributes;
    public KeyParameters privateKeyParameters;

    public Header(byte[] header) throws IOException, CertificateException {
        ASN1Sequence seq = ASN1Sequence.getInstance(header);
        //   if (asn1Sequence.size() != 2) throw new RuntimeException("Primary should have 2 elements");
        // halfKey = BEROctetString.getInstance(asn1Sequence.getObjectAt(0)).getOctets();


        ASN1Sequence seq2 = null;
        try {
            seq2 = ASN1Sequence.getInstance(seq.getObjectAt(0));
        } catch (Exception e) {
           e.printStackTrace();
        }

        if (seq.size() > 0 && seq2 != null) {
            for (ASN1Encodable tagObj : seq2) {
                if(tagObj instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tag = ASN1TaggedObject.getInstance(tagObj);

                    switch (tag.getTagNo()) {
                        case 5:
                            // byte[] cert = el
                            certificate = X509Reader.decodeCert(tagObj.toASN1Primitive().getEncoded());

                            break;
                        case 6:
                            certificate2 = X509Reader.decodeCert(tagObj.toASN1Primitive().getEncoded());
                            break;
                        case 10:
                            publicX = ASN1OctetString.getInstance(tag.getObject().getEncoded()).getOctets();
                            break;
                    }
                }
                if(tagObj instanceof ASN1Sequence) {
                    ASN1Sequence seq3 = ASN1Sequence.getInstance(tagObj);
                    privateKeyParameters = KeyParameters.getInstance(seq3);
                }
                if(tagObj instanceof DERBitString) {
                    attributes = DERBitString.getInstance(tagObj);
                }
            }
        }

        if (seq.size() > 1){
            hMACKey = BEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
        }

        if (hMACKey == null || attributes == null || privateKeyParameters == null || publicX == null)
            throw new RuntimeException("Ошибка в данных header.key.");
    }

    public static Header getInstance(byte[] header) throws IOException, CertificateException {
        return new Header(header);
    }

    @Override
    public String toString() {
        return "Header{" +
                "hMACKey=" + Arrays.toString(hMACKey) +
                ", publicX=" + Arrays.toString(publicX) +
                ", certificate=" + certificate +
                ", certificate2=" + certificate2 +
                ", attributes=" + attributes +
                ", privateKeyParameters=" + privateKeyParameters +
                '}';
    }
}
