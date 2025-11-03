package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

import artificialrobotics.com.SigningAuthorisation.certificates.CertificateLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;

/**
 * Fabrik zum Laden öffentlicher Schlüssel aus verschiedenen Formaten.
 * Unterstützt:
 *  - PEM SPKI            : -----BEGIN PUBLIC KEY-----
 *  - PEM PKCS#1 (RSA)    : -----BEGIN RSA PUBLIC KEY-----
 *  - XML (RSAKeyValue)   : <RSAKeyValue>...</RSAKeyValue>
 *  - HEX (DER als Hex)   : reiner Hex-Text der DER-Struktur (SPKI oder PKCS#1)
 *
 * Hinweis: Für Public Keys existieren i. d. R. keine Keystores 
 *          Bei Zertifikaten soll der CertificateLoader verwendet werden.
 * 
 * Beispiele:
 * PublicKey pub1 = PublicKeyFactory.load(Path.of("keys"), "pub_spki.pem");   // BEGIN PUBLIC KEY
 * PublicKey pub2 = PublicKeyFactory.load(Path.of("keys"), "rsa_pub.xml");    // RSAKeyValue
 * PublicKey pub3 = PublicKeyFactory.load(Path.of("keys"), "rsa_pub.hex");    // DER als HEX
 */
public final class PublicKeyFactory {

    private static final Pattern HEX_RE = Pattern.compile("^[0-9a-fA-F\\s]+$");

    private PublicKeyFactory() {}

    /** Datei-basierter Loader: erkennt PEM/XML/HEX anhand des Inhalts. */
    public static PublicKey load(Path directory, String fileName) throws Exception {
        Path file = directory.resolve(fileName);
        //String lower = fileName.toLowerCase(Locale.ROOT);
        String text = Files.readString(file);

        // PEM
        if (text.contains("BEGIN PUBLIC KEY") || text.contains("BEGIN RSA PUBLIC KEY")) {
            PEMPublicKeyLoader l = new PEMPublicKeyLoader(directory, fileName);
            l.load();
            return l.getPublicKey();
        }
        // XML
        if (text.contains("<RSAKeyValue")) {
            RSAXmlPublicKeyLoader l = new RSAXmlPublicKeyLoader(directory, fileName);
            l.load();
            return l.getPublicKey();
        }
        // HEX
        String trimmed = text.trim();
        if (!trimmed.isEmpty()
                && HEX_RE.matcher(trimmed).matches()
                && (trimmed.replaceAll("\\s+","").length() % 2 == 0)) {
            RSAHexPublicKeyLoader l = new RSAHexPublicKeyLoader(directory, fileName);
            l.load();
            return l.getPublicKey();
        }

        throw new IllegalArgumentException("Unbekanntes Public-Key-Format in Datei: " + fileName);
    }

    /** Variante A: Public Key direkt aus einem bereits konfigurierten CertificateLoader. */
    public static PublicKey loadFromCertificate(CertificateLoader certificateLoader) throws Exception {
        certificateLoader.load();
        X509Certificate cert = certificateLoader.getCertificate();
        if (cert == null) {
            throw new IllegalStateException("CertificateLoader lieferte kein Zertifikat (null).");
        }
        return cert.getPublicKey();
    }

    /** Variante B (Komfort): Public Key aus einem PEM-Zertifikat (oder Kette: erstes Zertifikat). */
    public static PublicKey loadFromCertificate(Path directory, String certFileName) throws Exception {
        CertificateLoader loader = new PEMCertificateLoader(directory, certFileName);
        return loadFromCertificate(loader);
    }
}
