package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Path;

/** 
 * Lädt RSA Private Key aus Hex-Text (DER-Bytes in Hex).
 *  Unterstützt PKCS#8 (direkt) und PKCS#1 (wird nach PKCS#8 umhüllt). 
 *  
 */
public class RSAHexPrivateKeyLoader extends PrivateKeyLoader {

    public RSAHexPrivateKeyLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws Exception {
        String hex = readFileString().replaceAll("\\s+", "");
        if (hex.isEmpty() || (hex.length() % 2 != 0)) {
            throw new IllegalArgumentException("Invalid HEX content");
        }
        byte[] der = hexToBytes(hex);

        byte[] pkcs8;
        if (looksLikePkcs8(der)) {
            pkcs8 = der;
        } else if (looksLikePkcs1RsaPrivateKey(der)) {
            pkcs8 = RSAPKCS1PrivateKeyLoader.wrapPkcs1ToPkcs8ForFriend(der); // kleine Brücke (s.u.)
        } else {
            throw new IllegalArgumentException("HEX does not look like PKCS#8 or PKCS#1 RSA private key");
        }

        this.privateKey = buildPkcs8PrivateKey(pkcs8);
    }

    private static PrivateKey buildPkcs8PrivateKey(byte[] pkcs8) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    private static boolean looksLikePkcs8(byte[] der) {
        // Sehr grob: SEQUENCE + (Version=0) + AlgorithmIdentifier + OCTET STRING ...
        return der.length > 16 && (der[0] == 0x30); // minimaler Check
    }

    private static boolean looksLikePkcs1RsaPrivateKey(byte[] der) {
        // Sehr grob: SEQUENCE + Version=0 + INTEGER(n) + INTEGER(e) + INTEGER(d) + ...
        return der.length > 16 && der[0] == 0x30;
    }

    private static byte[] hexToBytes(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            int b = Integer.parseInt(s.substring(2*i, 2*i+2), 16);
            out[i] = (byte) b;
        }
        return out;
    }

    // --- kleine „friend“-Brücke: wiederverwende PKCS#1→PKCS#8 aus dem ersten Loader ---
    // (du kannst alternativ die Methode in ein gemeinsames Util auslagern)
    private static class RSAPKCS1PrivateKeyLoader {
        static byte[] wrapPkcs1ToPkcs8ForFriend(byte[] pkcs1) {
            byte[] rsaOid = new byte[] { 0x06, 0x09, 0x2a,(byte)0x86,0x48,(byte)0x86,(byte)0xf7,0x0d,0x01,0x01,0x01 };
            byte[] nullParam = new byte[] { 0x05, 0x00 };
            byte[] algId = derSeq(concat(rsaOid, nullParam));
            byte[] version = new byte[] { 0x02, 0x01, 0x00 };
            byte[] privateKeyOctet = derOctetString(pkcs1);
            byte[] pkcs8Inner = concat(version, algId, privateKeyOctet);
            return derSeq(pkcs8Inner);
        }
        private static byte[] derSeq(byte[] content){return concat(new byte[]{0x30}, derLen(content.length), content);}
        private static byte[] derOctetString(byte[] content){return concat(new byte[]{0x04}, derLen(content.length), content);}
        private static byte[] derLen(int len){
            if (len < 0x80) return new byte[]{ (byte)len };
            byte[] tmp = new byte[]{ (byte)(len>>>24),(byte)(len>>>16),(byte)(len>>>8),(byte)len };
            int off=0; while (off<tmp.length && tmp[off]==0) off++;
            int n = tmp.length-off;
            byte[] out = new byte[1+n]; out[0]=(byte)(0x80|n);
            System.arraycopy(tmp,off,out,1,n); return out;
        }
        private static byte[] concat(byte[]... arrs){int len=0; for (byte[] a:arrs) len+=a.length;
            byte[] out=new byte[len]; int p=0; for (byte[] a:arrs){System.arraycopy(a,0,out,p,a.length); p+=a.length;} return out;}
    }
}