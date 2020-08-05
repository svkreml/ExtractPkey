package svkreml.extractKey;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import svkreml.extractKey.dto.Container;
import svkreml.extractKey.dto.ProviderType;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

public class PrivateKeyExport {
    private static ASN1Object EncodePrivateKey(Container container) throws IOException {
        AlgorithmIdentifier algorithm = container.header().privateKeyParameters.algorithm;
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                        ProviderType.getSignAlgorithmId(ProviderType.getProviderType(container.header().privateKeyParameters.algorithm.getAlgorithm())),
                        algorithm.getParameters()
                        );
        return new DERSequence(
                new ASN1Encodable[]{
                        new ASN1Integer(0),
                        algorithmIdentifier,
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
