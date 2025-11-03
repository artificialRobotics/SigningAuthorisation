package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/** Lädt RSA Public Key aus Hex-Text (DER-Bytes als Hex).
 *  Erkennt X.509 SPKI direkt; PKCS#1 wird zu SPKI umhüllt. */
public class RSAHexPublicKeyLoader extends PublicKeyLoader {

    public RSAHexPublicKeyLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws Exception {
        String hex = readFileString().replaceAll("\\s+",""); // nur Hex
        if (hex.isEmpty() || (hex.length() % 2 != 0)) {
            throw new IllegalArgumentException("Invalid HEX content");
        }
        byte[] der = hexToBytes(hex);

        byte[] spki = looksLikeSpki(der) ? der
                    : wrapPkcs1ToSpkiIfRsa(der);

        this.publicKey = buildRsaFromSpki(spki);
    }

    private static PublicKey buildRsaFromSpki(byte[] spki) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
    }

    private static byte[] wrapPkcs1ToSpkiIfRsa(byte[] derPkcs1) {
        // Wir hüllen „blind“ als RSAPublicKey → SPKI ein (scheitert später, wenn kein gültiges PKCS#1)
        return PEMPublicKeyLoader.wrapPkcs1RsaToSpki(derPkcs1);
    }

    private static boolean looksLikeSpki(byte[] der) {
        // sehr grob: SEQUENCE (30) … enthält AlgId + BIT STRING
        return der.length > 8 && der[0] == 0x30;
    }

    private static byte[] hexToBytes(String s) {
        int n = s.length() / 2; byte[] out = new byte[n];
        for (int i=0;i<n;i++) out[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
        return out;
    }
}