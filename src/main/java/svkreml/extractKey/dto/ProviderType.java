package svkreml.extractKey.dto;


import lombok.Getter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;

public enum ProviderType {
    CryptoPro_2001(75),
    CryptoPro_2012_512(80),
    CryptoPro_2012_1024(81);

    @Getter
    final int code;

    ProviderType(int i) {
        this.code = i;
    }


    public static ProviderType getProviderType(ASN1ObjectIdentifier algId) {
        if (algId.equals(CryptoProObjectIdentifiers.gostR3410_2001DH))
            return ProviderType.CryptoPro_2001;
        if (algId.equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256))
            return ProviderType.CryptoPro_2012_512;
        if (algId.equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512))
            return ProviderType.CryptoPro_2012_1024;

        throw new RuntimeException("Неподдерживаемый OID: " + algId);
    }

    public static ASN1ObjectIdentifier getSignAlgorithmId(Integer provider) {
        switch (provider) {
            case 75:
                return CryptoProObjectIdentifiers.gostR3410_2001DH;
            case 80:
                return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
            case 81:
                return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
            default:
                throw new RuntimeException("Неподдерживаемый криптопровайдер: " + provider);
        }
    }


    public static ASN1ObjectIdentifier getSignAlgorithmId(ProviderType provider) {
        switch (provider) {
            case CryptoPro_2001:
                return CryptoProObjectIdentifiers.gostR3410_2001DH;
            case CryptoPro_2012_512:
                return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
            case CryptoPro_2012_1024:
                return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
            default:
                throw new RuntimeException("Неподдерживаемый криптопровайдер: " + provider);
        }
    }
}
