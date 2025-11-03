package artificialrobotics.com.SigningAuthorisation.signingKeys;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.security.GeneralSecurityException;
import java.nio.file.Path;

/**
 * Loader für PKCS#8-PEM-Schlüssel:
 *  - "-----BEGIN PRIVATE KEY-----" (unverschlüsselt)
 *  - "-----BEGIN ENCRYPTED PRIVATE KEY-----" (verschlüsselt, Passwort nötig)
 *  
 *  Fokus auf RSA/ECDSA (eIDAS-typisch). Die Implementierung versucht automatisch RSA, dann EC, dann (falls verfügbar) Ed25519/Ed448.
 */
public class PKCS8KeyLoader extends PrivateKeyLoader {

    /** Optional: Passwort für "ENCRYPTED PRIVATE KEY" (null, wenn unverschlüsselt). */
    protected final char[] password;

    public PKCS8KeyLoader(Path directory, String fileName) {
        this(directory, fileName, null);
    }

    public PKCS8KeyLoader(Path directory, String fileName, char[] password) {
        super(directory, fileName);
        this.password = password;
    }

    @Override
    public void load() throws Exception {
        String pem = readFileString().replace("\r", "");

        if (pem.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password required for ENCRYPTED PRIVATE KEY");
            }
            byte[] enc = base64Between(pem,
                    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                    "-----END ENCRYPTED PRIVATE KEY-----");
            this.privateKey = loadEncryptedPkcs8(enc, password);
        } else if (pem.contains("BEGIN PRIVATE KEY")) {
            byte[] pkcs8 = base64Between(pem,
                    "-----BEGIN PRIVATE KEY-----",
                    "-----END PRIVATE KEY-----");
            this.privateKey = buildPrivateKeyFromPkcs8(pkcs8);
        } else {
            throw new IllegalArgumentException("Unsupported PEM format: expected (ENCRYPTED) PRIVATE KEY");
        }
    }

    // ---- Helpers ----

    private static byte[] base64Between(String text, String begin, String end) {
        int i = text.indexOf(begin);
        int j = text.indexOf(end);
        if (i < 0 || j < i) throw new IllegalArgumentException("PEM boundaries not found");
        String b64 = text.substring(i + begin.length(), j).replaceAll("\\s+", "");
        return Base64.getMimeDecoder().decode(b64);
    }

    private static PrivateKey loadEncryptedPkcs8(byte[] encPkcs8, char[] password) throws Exception {
        // Entschlüsselt PKCS#8 mittels JCE (PBES2/PBKDF2/AES, je nach Header)
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(encPkcs8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(epki.getAlgName());
        SecretKey pbeKey = skf.generateSecret(new PBEKeySpec(password));
        Cipher cipher = Cipher.getInstance(epki.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, epki.getAlgParameters());
        PKCS8EncodedKeySpec keySpec = epki.getKeySpec(cipher);
        return buildPrivateKeyFromPkcs8(keySpec.getEncoded());
    }

    /** Versucht RSA → EC → Ed25519 → Ed448 in dieser Reihenfolge. */
    private static PrivateKey buildPrivateKeyFromPkcs8(byte[] pkcs8) throws GeneralSecurityException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);

        // 1) RSA
        try { return KeyFactory.getInstance("RSA").generatePrivate(spec); } catch (Exception ignored) {}

        // 2) EC (ECDSA)
        try { return KeyFactory.getInstance("EC").generatePrivate(spec); } catch (Exception ignored) {}

        // 3) EdDSA (falls vom JDK/Provider unterstützt)
        try { return KeyFactory.getInstance("Ed25519").generatePrivate(spec); } catch (Exception ignored) {System.out.println(ignored);}
        try { return KeyFactory.getInstance("Ed448").generatePrivate(spec); } catch (Exception ignored) {System.out.println(ignored);}

        // 4) Nicht erkannt
        throw new GeneralSecurityException("Unknown/unsupported PKCS#8 private key algorithm");
    }
}