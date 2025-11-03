package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/** Lädt unverschlüsselte PKCS#1 RSA-Private-Keys (PEM) und konvertiert sie nach PKCS#8. */
public class RSAPKCS1PrivateKeyLoader extends PrivateKeyLoader {

    public RSAPKCS1PrivateKeyLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws Exception {
        String pem = readFileString().replace("\r", "");
        String begin = "-----BEGIN RSA PRIVATE KEY-----";
        String end   = "-----END RSA PRIVATE KEY-----";
        int i = pem.indexOf(begin), j = pem.indexOf(end);
        if (i < 0 || j < i) {
            throw new IllegalArgumentException("PEM does not contain an unencrypted RSA PRIVATE KEY (PKCS#1)");
        }
        String b64 = pem.substring(i + begin.length(), j).replaceAll("\\s+", "");
        byte[] pkcs1 = Base64.getMimeDecoder().decode(b64);

        // in PKCS#8 hüllen und als PrivateKey bauen
        byte[] pkcs8 = wrapPkcs1ToPkcs8(pkcs1);
        this.privateKey = buildPkcs8PrivateKey(pkcs8);
    }

    private static PrivateKey buildPkcs8PrivateKey(byte[] pkcs8) throws GeneralSecurityException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        // „RSA“ KeyFactory erkennt PKCS#8 automatisch
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * PKCS#1 → PKCS#8 konvertieren:
     * PKCS#8 = SEQ { version=0, algId = rsaEncryption (NULL), privateKey = OCTET STRING(pkcs1) }
     */
    private static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1) {
        // ASN.1 Bausteine (DER) für rsaEncryption OID 1.2.840.113549.1.1.1 und NULL
        byte[] rsaOid = new byte[] { 0x06, 0x09, 0x2a,(byte)0x86,0x48,(byte)0x86,(byte)0xf7,0x0d,0x01,0x01,0x01 };
        byte[] nullParam = new byte[] { 0x05, 0x00 };

        byte[] algId = derSeq(concat(rsaOid, nullParam));
        byte[] version = new byte[] { 0x02, 0x01, 0x00 }; // INTEGER 0
        byte[] privateKeyOctet = derOctetString(pkcs1);

        byte[] pkcs8Inner = concat(version, algId, privateKeyOctet);
        return derSeq(pkcs8Inner);
    }

    // ---- Minimal-DER-Helper (nur was wir brauchen) ----
    private static byte[] derSeq(byte[] content) {
        return concat(new byte[]{0x30}, derLen(content.length), content);
    }
    private static byte[] derOctetString(byte[] content) {
        return concat(new byte[]{0x04}, derLen(content.length), content);
    }
    private static byte[] derLen(int len) {
        if (len < 0x80) return new byte[]{ (byte)len };
        // lange Längen – bis 4 Bytes
        byte[] tmp = intToBytes(len);
        int off = 0; while (off < tmp.length && tmp[off] == 0) off++;
        int n = tmp.length - off;
        byte[] out = new byte[1 + n];
        out[0] = (byte)(0x80 | n);
        System.arraycopy(tmp, off, out, 1, n);
        return out;
    }
    private static byte[] intToBytes(int v) {
        return new byte[]{ (byte)(v>>>24),(byte)(v>>>16),(byte)(v>>>8),(byte)v };
    }
    private static byte[] concat(byte[]... arrs) {
        int len=0; for (byte[] a: arrs) len+=a.length;
        byte[] out=new byte[len]; int p=0;
        for (byte[] a: arrs){ System.arraycopy(a,0,out,p,a.length); p+=a.length; }
        return out;
    }
}
