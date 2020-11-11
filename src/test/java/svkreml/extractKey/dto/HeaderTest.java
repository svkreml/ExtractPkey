package svkreml.extractKey.dto;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.testng.Assert;
import org.testng.annotations.Test;
import svkreml.extractKey.FileManager;

import java.io.IOException;
import java.security.cert.CertificateException;

public class HeaderTest {

    @Test
    public void test() throws IOException, CertificateException {

        Header header = new Header(FileManager.read("00000000.000/header.key"));
        Assert.assertEquals(header.certificate.getEncoded(), FileManager.read("00000000.000/user.crt"));
        Assert.assertEquals(header.certificate2, null);
        Assert.assertEquals(header.attributes, DERBitString.fromByteArray(Hex.decode("030206C0")));

        Assert.assertEquals(header.hMACKey,Hex.decode("51c66f7d"));
        Assert.assertEquals(header.publicX, Hex.decode("d25d2118c10e4c6c"));

        Assert.assertEquals(header.privateKeyParameters.toString(),
                new KeyParameters(
                        AlgorithmIdentifier.getInstance(Hex.decode("301f06082a85030701010601301306072a85030202240006082a85030701010202")),
                        DERBitString.getInstance(Hex.decode("03020520"))
                ).toString()
        );
    }
}
