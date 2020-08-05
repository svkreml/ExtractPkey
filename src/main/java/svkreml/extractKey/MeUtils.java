package svkreml.extractKey;


import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class MeUtils {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static byte[] concatBytes(byte[]... bytesArray) {
        int size = 0;
        for (byte[] bytes : bytesArray) {
            size += bytes.length;
        }
        byte[] result = new byte[size];
        int pos = 0;
        for (byte[] bytes : bytesArray) {
            System.arraycopy(bytes, 0, result, pos, bytes.length);
            pos += bytes.length;
        }
        return result;
    }


    @SneakyThrows
    public static String getThumbprint(X509Certificate cert) {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = Hex.toHexString(digest);
        return digestHex.toLowerCase();
    }

    @SneakyThrows
    public static String getThumbprint(byte[] cert) {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert);
        byte[] digest = md.digest();
        String digestHex = Hex.toHexString(digest);
        return digestHex.toLowerCase();
    }

    public static X500Name parseX500NameFromString(String x500NameString) {
        return new X500Name(X500Name.getDefaultStyle().fromString(x500NameString));
    }

    public static byte[] normalizeDer(byte[] bytes) {
        if (bytes[0] == '-' && bytes[1] == '-') {
            bytes = new String(bytes).trim().
                    replaceAll("-----[A-Z0-9 ]{3,90}-----", "").getBytes();
            bytes = Base64.getMimeDecoder().decode(bytes);
        } else if ((bytes[0] == 77) && (bytes[1] == 73)) {
            bytes = Base64.getMimeDecoder().decode(bytes);
        }
        return bytes;
    }
}
