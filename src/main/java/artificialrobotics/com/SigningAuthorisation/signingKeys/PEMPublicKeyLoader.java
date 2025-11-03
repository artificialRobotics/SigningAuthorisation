package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;

/**
 * Lädt Public Keys aus PEM:
 *  - "-----BEGIN PUBLIC KEY-----" (X.509 SubjectPublicKeyInfo / SPKI, generisch)
 *  - "-----BEGIN RSA PUBLIC KEY-----" (PKCS#1, wird nach SPKI „umhüllt“)
 */
public class PEMPublicKeyLoader extends PublicKeyLoader {

    public PEMPublicKeyLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws Exception {
        String pem = readFileString().replace("\r", "");

        if (pem.contains("BEGIN PUBLIC KEY")) {
            byte[] spki = base64Between(pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
            this.publicKey = buildFromSpki(spki);
        } else if (pem.contains("BEGIN RSA PUBLIC KEY")) {
            byte[] pkcs1 = base64Between(pem, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----");
            byte[] spki = wrapPkcs1RsaToSpki(pkcs1);
            this.publicKey = buildFromSpki(spki);
        } else {
            throw new IllegalArgumentException("Unsupported PEM: expected BEGIN PUBLIC KEY or BEGIN RSA PUBLIC KEY");
        }
    }

    // ---- Helpers ----
    private static byte[] base64Between(String text, String begin, String end) {
        int i = text.indexOf(begin), j = text.indexOf(end);
        if (i < 0 || j < i) throw new IllegalArgumentException("PEM boundaries not found: " + begin);
        String b64 = text.substring(i + begin.length(), j).replaceAll("\\s+", "");
        return Base64.getMimeDecoder().decode(b64);
    }

    /** Versucht RSA → EC → Ed25519 → Ed448 anhand SPKI (X.509) */
    private static PublicKey buildFromSpki(byte[] spki) throws GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spki);
        try { return KeyFactory.getInstance("RSA").generatePublic(spec); } catch (Exception ignored) {}
        try { return KeyFactory.getInstance("EC").generatePublic(spec); } catch (Exception ignored) {}
        try { return KeyFactory.getInstance("Ed25519").generatePublic(spec); } catch (Exception ignored) {}
        try { return KeyFactory.getInstance("Ed448").generatePublic(spec); } catch (Exception ignored) {}
        throw new GeneralSecurityException("Unsupported/unknown SPKI public key");
    }

    /**
     * PKCS#1 RSAPublicKey → X.509 SubjectPublicKeyInfo (SPKI) umhüllen:
     * SPKI = SEQ { algId = rsaEncryption(NULL), subjectPublicKey = BIT STRING( RSAPublicKey DER ) }
     */
    static byte[] wrapPkcs1RsaToSpki(byte[] pkcs1) {
        byte[] rsaOid = new byte[]{ 0x06,0x09,0x2a,(byte)0x86,0x48,(byte)0x86,(byte)0xf7,0x0d,0x01,0x01,0x01 };
        byte[] nullParam = new byte[]{ 0x05,0x00 };
        byte[] algId = derSeq(concat(rsaOid, nullParam));
        byte[] bitString = derBitString(pkcs1); // enthält ungenutzte Bits = 0 vor dem Inhalt
        byte[] spkiInner = concat(algId, bitString);
        return derSeq(spkiInner);
    }

    // Minimal-DER-Helper
    private static byte[] derSeq(byte[] content){ return concat(new byte[]{0x30}, derLen(content.length), content); }
    private static byte[] derBitString(byte[] content) {
        byte[] withUnused = concat(new byte[]{0x00}, content); // 0 = unused bits
        return concat(new byte[]{0x03}, derLen(withUnused.length), withUnused);
    }
    private static byte[] derLen(int len){
        if (len < 0x80) return new byte[]{ (byte)len };
        byte[] tmp = new byte[]{ (byte)(len>>>24),(byte)(len>>>16),(byte)(len>>>8),(byte)len };
        int off=0; while (off<tmp.length && tmp[off]==0) off++;
        int n = tmp.length-off;
        byte[] out = new byte[1+n]; out[0]=(byte)(0x80|n);
        System.arraycopy(tmp,off,out,1,n); return out;
    }
    private static byte[] concat(byte[]... arrs){
        int len=0; for (byte[] a:arrs) len+=a.length;
        byte[] out=new byte[len]; int p=0;
        for (byte[] a:arrs){ System.arraycopy(a,0,out,p,a.length); p+=a.length; }
        return out;
    }
}