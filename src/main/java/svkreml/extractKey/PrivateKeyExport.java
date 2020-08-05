package svkreml.extractKey;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import svkreml.extractKey.dto.Container;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

public class PrivateKeyExport {
    private static ASN1Object EncodePrivateKey(Container container) throws IOException {
        return new DERSequence(
                new ASN1Encodable[]{
                        new ASN1Integer(0),
                        new DERSequence(
                                new ASN1Encodable[]{
                                        new ASN1ObjectIdentifier("1.2.643.7.1.1.1.1"),
                                        new DERSequence(
                                                new ASN1ObjectIdentifier[]{
                                                        new ASN1ObjectIdentifier("1.2.643.2.2.36.0"),
                                                        new ASN1ObjectIdentifier("1.2.643.7.1.1.2.2")
                                                }
                                        )
                                }
                        ),
                        new DEROctetString(new ASN1Integer(container.GetPrivateKey()))
                }
        );
    }

    public void Export(Container container, OutputStream output) throws IOException {
        ASN1Object privateKey = EncodePrivateKey(container);
        PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
        try (OutputStreamWriter sw = new OutputStreamWriter(output)) {
            PemWriter writer = new PemWriter(sw);
            writer.writeObject(pemObject);
            writer.flush();
        }
    }
}


    /*
    *  1.2.643.7.1.1.1.1 gost2012PublicKey256 (GOST R 34.10-2012 256 bit public key)
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.643.2.2.36.0 cryptoProSignXA (CryptoPro ell.curve XA for GOST R 34.10-2001)
      OBJECT IDENTIFIER 1.2.643.7.1.1.2.2 gos
      *
      * */
