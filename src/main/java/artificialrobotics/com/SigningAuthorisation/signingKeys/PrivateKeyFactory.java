package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Fabrik zum Laden privater Schlüssel aus verschiedenen Formaten.
 * Unterstützt:
 *  - PKCS#8 PEM           : -----BEGIN PRIVATE KEY-----
 *  - PKCS#1 PEM (RSA)     : -----BEGIN RSA PRIVATE KEY-----
 *  - XML (RSAKeyValue)    : <RSAKeyValue>...</RSAKeyValue>
 *  - HEX (DER als Hex)    : reiner Hex-Text der DER-Struktur (PKCS#8 oder PKCS#1)
 *  - Keystore (PKCS12/JKS): .p12/.pfx/.jks (mit Passwort & Alias)
 */
public final class PrivateKeyFactory {

    private static final Pattern HEX_RE = Pattern.compile("^[0-9a-fA-F\\s]+$");

    private PrivateKeyFactory() {}

    /** Einfacher Einstieg: lädt Key aus Datei (PEM/PKCS1/XML/HEX) anhand Inhalt/Endung. */
    public static PrivateKey load(Path directory, String fileName) throws Exception {
        Path file = directory.resolve(fileName);
        String lower = fileName.toLowerCase(Locale.ROOT);

        // Keystore über Endung
        if (lower.endsWith(".p12") || lower.endsWith(".pfx") || lower.endsWith(".jks")) {
            throw new IllegalArgumentException(
                "Keystore erkannt – bitte loadFromKeystore(...) mit Passwort/Alias verwenden.");
        }

        String text = Files.readString(file);

        // Inhaltssniffing (robust gegen falsche Endungen)
        if (text.contains("BEGIN ENCRYPTED PRIVATE KEY") || text.contains("BEGIN PRIVATE KEY")) {
            // PKCS#8 (unverschlüsselt oder encrypted)
        	PKCS8KeyLoader l = text.contains("BEGIN ENCRYPTED PRIVATE KEY")
                    ? new PKCS8KeyLoader(directory, fileName, promptMissingPassword())
                    : new PKCS8KeyLoader(directory, fileName);
            l.load();
            return l.getPrivateKey();
        }
        if (text.contains("BEGIN RSA PRIVATE KEY")) {
            // PKCS#1 RSA (unverschlüsselt)
            RSAPKCS1PrivateKeyLoader l = new RSAPKCS1PrivateKeyLoader(directory, fileName);
            l.load();
            return l.getPrivateKey();
        }
        if (text.contains("<RSAKeyValue")) {
            // XML (RSAKeyValue)
            RSAXmlPrivateKeyLoader l = new RSAXmlPrivateKeyLoader(directory, fileName);
            l.load();
            return l.getPrivateKey();
        }
        // HEX?
        String trimmed = text.trim();
        if (!trimmed.isEmpty() && HEX_RE.matcher(trimmed).matches() && (trimmed.replaceAll("\\s+","").length() % 2 == 0)) {
            RSAHexPrivateKeyLoader l = new RSAHexPrivateKeyLoader(directory, fileName);
            l.load();
            return l.getPrivateKey();
        }

        throw new IllegalArgumentException("Unbekanntes Private-Key-Format in Datei: " + fileName);
    }

    /** Keystore-Variante: PKCS12/JKS mit Store-Passwort, Alias und optional separatem Key-Passwort. */
    public static PrivateKey loadFromKeystore(
            Path directory,
            String keystoreFileName,
            String keystoreType,        // "PKCS12" oder "JKS" (null → PKCS12)
            char[] storePassword,
            String keyAlias,
            char[] keyPassword          // null → storePassword
    ) throws Exception {
        KeystorePrivateKeyLoader l = new KeystorePrivateKeyLoader(
                directory, keystoreFileName,
                keystoreType, storePassword, keyAlias, keyPassword);
        l.load();
        return l.getPrivateKey();
    }

    /** Placeholder: passe die Passwortbeschaffung an deine Umgebung an (UI/Env/Secrets). */
    private static char[] promptMissingPassword() {
        throw new IllegalArgumentException("Passwort für ENCRYPTED PRIVATE KEY erforderlich – bitte Passwort über PEMPrivateKeyLoader(...) übergeben.");
    }
}

