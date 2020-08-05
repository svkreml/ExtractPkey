package svkreml.extractKey.dto;

import lombok.AllArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.jcajce.provider.digest.GOST3411;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import svkreml.extractKey.Lazy;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public abstract class Container {

    private static final byte[] Gost28147_TC26ParamSetZ =
            {
                    0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
                    0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
                    0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
                    0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
                    0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
                    0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
                    0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
                    0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
            };
    protected String _pin;
    private final Lazy<Data> _data;
    private final Lazy<Header> _headerObj;
    private final Lazy<Mask> _masksObj;
    private final Lazy<Primary> _primaryObj;

    Container(String pin) {
        _pin = pin;
        _data = new Lazy<>(this::LoadContainerData);
        _headerObj = new Lazy<>(this::LoadHeader);
        _primaryObj = new Lazy<>(this::LoadPrimary);
        _masksObj = new Lazy<>(this::LoadMasks);
    }

    private static void CheckPublicKey(ECDomainParameters domainParams, BigInteger privateKey, byte[] publicX) {
        ECPoint point = domainParams.getG().multiply(privateKey).normalize();
        byte[] x = Arrays.reverse(point.getAffineXCoord().getEncoded());
        if (!Arrays.areEqual(publicX, Arrays.copyOf(x, publicX.length)))
            throw new RuntimeException(
                    "Не удалось проверить корректность открытого ключа (некорректный ПИН-код?).");
    }

    private static void XorMaterial(byte[] buf36, byte[] buf5c, byte[] src) {
        for (int i = 0; i < src.length; ++i) {
            buf36[i] = (byte) (src[i] ^ 0x36);
            buf5c[i] = (byte) (src[i] ^ 0x5C);
        }
    }

    public ECDomainParameters PublicKeyAlg() {
        return ECGOST3410NamedCurves.getByOID((ASN1ObjectIdentifier) ((DERSequence) header().privateKeyParameters.algorithm.getParameters()).getObjectAt(0));
    }

    public Header header() {
        return _headerObj.get();
    }

    public Primary Primary() {
        return _primaryObj.get();
    }

    public Mask Masks() {
        return _masksObj.get();
    }

    private Mask
    LoadMasks() {
        return Mask.getInstance(_data.get().masks);
    }

    private Primary LoadPrimary() {
        return Primary.getInstance(_data.get().primary);
    }

    private Header LoadHeader() {
        try {
            return Header.getInstance(_data.get().header);
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    public BigInteger GetPrivateKey() {
        byte[] pinArray = (_pin == null ? "" : _pin).getBytes(StandardCharsets.US_ASCII);
        byte[] decodeKey = GetDecodeKey(Masks().salt, pinArray);
        BigInteger primKeyWithMask = DecodePrimaryKey(decodeKey, Primary().key);
        //  ECKeyParameters.


        //   ASN1Encodable parameters = header().privateKeyParameters.algorithm.getParameters()l

        BigInteger masksKey = new BigInteger(1, Masks().key);
        ECKeyGenerationParameters param = new ECKeyGenerationParameters(PublicKeyAlg(), new SecureRandom());
        BigInteger maskInv = masksKey.modInverse(param.getDomainParameters().getCurve().getOrder());

        BigInteger privateKey = primKeyWithMask.multiply(maskInv).mod(param.getDomainParameters().getCurve().getOrder());

        CheckPublicKey(param.getDomainParameters(), privateKey, header().publicX);

        return privateKey;
    }

    public byte[] GetRawcertificate() throws CertificateEncodingException {
        if (header().certificate != null)
            return header().certificate.getEncoded();

        if (header().certificate2 != null)
            return header().certificate2.getEncoded();

        throw new RuntimeException("Контейнер не содержит сертификата.");
    }

    private BigInteger DecodePrimaryKey(byte[] decodeKey, byte[] primaryKey) {
        GOST28147Engine engine = new GOST28147Engine();

        byte[] sbox =
                ProviderType.getProviderType(header().privateKeyParameters.algorithm.getAlgorithm()) == ProviderType.CryptoPro_2001
                        ? GOST28147Engine.getSBox("E-A")
                        : Gost28147_TC26ParamSetZ;

        ParametersWithSBox param = new ParametersWithSBox(
                new KeyParameter(decodeKey), sbox);

        engine.init(false, param);

        byte[] buf = new byte[primaryKey.length];
        for (int i = 0; i < primaryKey.length; i += 8)
            engine.processBlock(primaryKey, i, buf, i);

        return new BigInteger(1, org.bouncycastle.util.Arrays.reverse(buf));
    }

    private byte[] GetDecodeKey(byte[] salt, byte[] pin) {
        byte[] pincode4 = new byte[pin.length * 4];
        for (int i = 0; i < pin.length; ++i)
            pincode4[i * 4] = pin[i];

        MessageDigest digest =
                ProviderType.getProviderType(header().privateKeyParameters.algorithm.getAlgorithm()) == svkreml.extractKey.dto.ProviderType.CryptoPro_2001
                        ? new GOST3411.Digest()
                        : new GOST3411.Digest2012_256();

        digest.update(salt, 0, salt.length);
        if (pin.length > 0)
            digest.update(pincode4, 0, pincode4.length);


        byte[] result = digest.digest();
        int len = ProviderType.getProviderType(header().privateKeyParameters.algorithm.getAlgorithm()) == svkreml.extractKey.dto.ProviderType.CryptoPro_2001 ? 32 : 64;
        byte[] material36 = new byte[len];
        byte[] material5c = new byte[len];

        byte[] current = Arrays.copyOf("DENEFH028.760246785.IUEFHWUIO.EF".getBytes(StandardCharsets.US_ASCII),
                len);

        len = pin.length > 0 ? 2000 : 2;
        for (int i = 0; i < len; ++i) {
            XorMaterial(material36, material5c, current);
            digest.reset();
            digest.update(material36, 0, material36.length);
            digest.update(result, 0, result.length);
            digest.update(material5c, 0, material5c.length);
            digest.update(result, 0, result.length);
            current = digest.digest();
        }

        XorMaterial(material36, material5c, current);
        digest.reset();
        digest.update(material36, 0, 32);
        digest.update(salt, 0, salt.length);
        digest.update(material5c, 0, 32);
        if (pin.length > 0)
            digest.update(pincode4, 0, pincode4.length);
        current = digest.digest();


        digest.reset();
        digest.update(current, 0, 32);

        return digest.digest();
    }

    protected abstract Data LoadContainerData();

    @AllArgsConstructor
    protected static class Data {
        public byte[] header;
        public byte[] masks;
        public byte[] masks2;
        public byte[] name;
        public byte[] primary;
        public byte[] primary2;
    }
}
