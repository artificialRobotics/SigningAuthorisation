package artificialrobotics.com.SigningAuthorisation.certificates;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/** Abstrakte Basis für alle Certificate-Loader.
 *  Erfordert Pfad + Dateiname und definiert die Lade-Schnittstelle. */
public abstract class CertificateLoader {

	 protected final Path directory;
	    protected final String fileName;

	    // Geschützte Felder für Zertifikate (Subklassen befüllen diese)
	    protected X509Certificate certificate;
	    protected List<X509Certificate> certificateChain = Collections.emptyList();

	    protected CertificateLoader(Path directory, String fileName) {
	        this.directory = directory;
	        this.fileName = fileName;
	        
	        System.out.println(".. loading Certificate: " + fileName + " from directory: " + directory );
	    }

	    /** Vollständiger Pfad zur Zertifikatsdatei. */
	    public Path filePath() {
	        return directory.resolve(fileName);
	    }

	    /** Lädt das/die Zertifikat(e) – von Subklassen zu implementieren. */
	    public abstract void load() throws IOException, CertificateException;

	    /** Getter für das Einzelzertifikat. */
	    public X509Certificate getCertificate() {
	        return certificate;
	    }

	    /** Getter für die Zertifikatskette. */
	    public List<X509Certificate> getCertificateChain() {
	        return certificateChain;
	    }

	    /** Hilfsfunktion: Datei lesen (für Subklassen nützlich). */
	    protected byte[] readFileBytes() throws IOException {
	        return Files.readAllBytes(filePath());
	    }
}
