package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * Lädt einen privaten Schlüssel aus einem Keystore (PKCS12 oder JKS).
 *
 * Erfordert:
 *  - keystoreType: "PKCS12" (empfohlen) oder "JKS"
 *  - storePassword: Passwort des Keystores
 *  - keyAlias: Alias des zu ladenden Schlüssels
 *  - keyPassword: Passwort für den Private Key (wenn null → storePassword wird verwendet)
 */
public class KeystorePrivateKeyLoader extends PrivateKeyLoader {

    private final String keystoreType;
    private final char[] storePassword;
    private final String keyAlias;
    private final char[] keyPassword; // darf null sein

    public KeystorePrivateKeyLoader(
            java.nio.file.Path directory,
            String fileName,
            String keystoreType,
            char[] storePassword,
            String keyAlias,
            char[] keyPassword) {
        super(directory, fileName);
        this.keystoreType = keystoreType != null ? keystoreType : "PKCS12";
        this.storePassword = storePassword;
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword; // kann null sein
    }

    @Override
    public void load() throws Exception {
        try (InputStream in = Files.newInputStream(filePath())) {
            KeyStore ks = KeyStore.getInstance(keystoreType);
            ks.load(in, storePassword);

            char[] kp = (keyPassword != null) ? keyPassword : storePassword;
            if (!ks.isKeyEntry(keyAlias)) {
                throw new IllegalArgumentException("Alias nicht gefunden oder kein Key-Entry: " + keyAlias);
            }

            Key key = ks.getKey(keyAlias, kp);
            if (key == null || !(key instanceof PrivateKey)) {
                throw new IllegalArgumentException("Alias enthält keinen PrivateKey: " + keyAlias);
            }
            this.privateKey = (PrivateKey) key;
        } finally {
            // Passwörter im Speicher löschen (Best Practice)
            if (storePassword != null) Arrays.fill(storePassword, '\0');
            if (keyPassword   != null) Arrays.fill(keyPassword,   '\0');
        }
    }
}
