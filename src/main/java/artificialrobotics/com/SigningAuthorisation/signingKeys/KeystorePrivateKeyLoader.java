package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public class KeystorePrivateKeyLoader {

    private final Path directory;
    private final String keystoreFileName;
    private final String keystoreType;     // "PKCS12" | "JKS" | null -> PKCS12
    private final char[] storePassword;    // darf null sein -> leeres PW
    private final String keyAlias;         // erforderlich
    private final char[] keyPassword;      // null -> fallback auf storePassword

    private PrivateKey privateKey;
    private List<X509Certificate> certificateChain = List.of();

    public KeystorePrivateKeyLoader(Path directory,
                                    String keystoreFileName,
                                    String keystoreType,
                                    char[] storePassword,
                                    String keyAlias,
                                    char[] keyPassword) {
        this.directory = Objects.requireNonNull(directory, "directory must not be null");
        this.keystoreFileName = Objects.requireNonNull(keystoreFileName, "keystoreFileName must not be null");
        this.keystoreType = (keystoreType == null || keystoreType.isBlank()) ? "PKCS12" : keystoreType.trim();
        this.storePassword = storePassword; // kann null sein
        this.keyAlias = Objects.requireNonNull(keyAlias, "keyAlias must not be null");
        this.keyPassword = keyPassword;     // kann null sein
    }

    public void load() throws Exception {
        Path ksPath = directory.resolve(keystoreFileName);
        if (!Files.exists(ksPath)) {
            throw new IllegalArgumentException("Keystore file not found: " + ksPath.toAbsolutePath());
        }

        try (InputStream in = Files.newInputStream(ksPath)) {
            String typeUpper = this.keystoreType.toUpperCase(Locale.ROOT);
            if (!typeUpper.equals("PKCS12") && !typeUpper.equals("JKS")) {
                throw new IllegalArgumentException("Unsupported keystoreType: " + keystoreType + " (use PKCS12 or JKS)");
            }

            KeyStore ks = KeyStore.getInstance(typeUpper);
            char[] storePwd = normalizePassword(this.storePassword);
            ks.load(in, storePwd);

            String effectiveAlias = resolveAlias(ks, this.keyAlias);
            if (effectiveAlias == null) {
                throw new IllegalArgumentException("Alias not found in keystore: " + this.keyAlias);
            }

            char[] keyPwd = (this.keyPassword != null) ? this.keyPassword : storePwd;

            Key key;
            try {
                key = ks.getKey(effectiveAlias, keyPwd);
            } catch (UnrecoverableKeyException e) {
                // Fallback: falls separates keyPassword falsch/leer war, noch mit Store-Passwort probieren
                if (!samePassword(keyPwd, storePwd)) {
                    try {
                        key = ks.getKey(effectiveAlias, storePwd);
                    } catch (UnrecoverableKeyException e2) {
                        throw new RuntimeException("Unable to recover private key (key password and store password failed).", e2);
                    }
                } else {
                    throw new RuntimeException("Unable to recover private key (wrong password).", e);
                }
            }

            if (!(key instanceof PrivateKey)) {
                throw new IllegalStateException("Entry for alias '" + effectiveAlias + "' is not a PrivateKey.");
            }
            this.privateKey = (PrivateKey) key;

            // Zertifikatskette laden (optional hilfreich z. B. für x5c)
            this.certificateChain = loadChain(ks, effectiveAlias);
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException("Failed to load private key from keystore: " + e.getMessage(), e);
        }
    }

    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            throw new IllegalStateException("Keystore not loaded yet – call load() first.");
        }
        return privateKey;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    /* ========================= Helpers ========================= */

    private static char[] normalizePassword(char[] pwd) {
        return (pwd == null) ? new char[0] : pwd;
    }

    private static boolean samePassword(char[] a, char[] b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    private static String resolveAlias(KeyStore ks, String requestedAlias) throws GeneralSecurityException {
        if (ks.containsAlias(requestedAlias)) return requestedAlias;

        // case-insensitive Fallback
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (a.equalsIgnoreCase(requestedAlias)) return a;
        }
        return null;
    }

    private static List<X509Certificate> loadChain(KeyStore ks, String alias) throws GeneralSecurityException {
        Certificate[] chain = ks.getCertificateChain(alias);
        List<X509Certificate> out = new ArrayList<>();
        if (chain != null) {
            for (Certificate c : chain) {
                if (c instanceof X509Certificate x) out.add(x);
            }
            return out;
        }
        // Single-Zertifikat als Fallback
        Certificate single = ks.getCertificate(alias);
        if (single instanceof X509Certificate x) out.add(x);
        return out;
    }
}
