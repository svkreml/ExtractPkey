package svkreml.extractKey;

import com.google.common.io.ByteStreams;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/*
 * конвертер в base64 и обратно в объекты
 * */
@Slf4j
public class X509Reader {
    static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    static final String END_CERT = "-----END CERTIFICATE-----";
    static DefaultAlgorithmNameFinder defaultAlgorithmNameFinder = new DefaultAlgorithmNameFinder();

    public static byte[] encodeCert(X509Certificate certificate) throws CertificateEncodingException {
        byte[] bytes = MeUtils.concatBytes(
                "-----BEGIN CERTIFICATE-----\n".getBytes(),
                Base64.getEncoder().encode(certificate.getEncoded()),
                "\n-----END CERTIFICATE-----\n".getBytes()
        );
        log.trace("encodeCert base64:\n" + new String(bytes));
        return bytes;
    }

    public static byte[] encodeCertRec(PKCS10CertificationRequest req) throws IOException {
        byte[] bytes = MeUtils.concatBytes(
                "-----BEGIN CERTIFICATE REQUEST-----\n".getBytes(),
                Base64.getEncoder().encode(req.getEncoded()),
                "\n-----END CERTIFICATE REQUEST-----\n".getBytes()
        );
        log.trace("encodeCertRec base64:\n" + new String(bytes));
        return bytes;
    }

    public static byte[] encodePrivateKey(PrivateKey privateKey) {
        byte[] bytes = MeUtils.concatBytes(
                "-----BEGIN PRIVATE KEY-----\n".getBytes(),
                Base64.getEncoder().encode(privateKey.getEncoded()),
                "\n-----END PRIVATE KEY-----\n".getBytes()
        );
        log.trace("encodePrivateKey base64:\n" + new String(bytes));
        return bytes;
    }

    public static X509CertificateHolder decodeCertHolder(byte[] input) throws IOException {
        return new X509CertificateHolder(MeUtils.normalizeDer(input));
    }

    public static X509Certificate decodeCert(byte[] input) throws CertificateException {


        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(MeUtils.normalizeDer(input))
        );
    }

    public static PKCS10CertificationRequest decodeCertRec(byte[] input) throws IOException {
        return new PKCS10CertificationRequest(MeUtils.normalizeDer(input));
    }

    public static PrivateKey decodePrivateKey(byte[] privateKeyBytes) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(MeUtils.normalizeDer(privateKeyBytes));
        KeyFactory factory = KeyFactory.getInstance(defaultAlgorithmNameFinder.getAlgorithmName(privateKeyInfo.getPrivateKeyAlgorithm()), "BC");
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
        return factory.generatePrivate(privKeySpec);
    }


    public static X509Certificate decodeCert(InputStream inputStream) throws IOException, CertificateException {
        return decodeCert(ByteStreams.toByteArray(inputStream));
    }

    public static X509CRLHolder decodeCrl(InputStream inputStream) throws IOException {
        return new X509CRLHolder(ByteStreams.toByteArray(inputStream));
    }

    public static X509CRLHolder decodeCrl(byte[] bytes) throws IOException {
        return new X509CRLHolder(bytes);
    }
}
