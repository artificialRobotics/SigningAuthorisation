package artificialrobotics.com.SigningAuthorisation.signingKeys;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

/** Abstrakte Basisklasse für Private-Key-Loader (Pfad + Dateiname + Getter). */
public abstract class PrivateKeyLoader {

    protected final Path directory;
    protected final String fileName;

    /** Geladener Private Key (Subklassen setzen dieses Feld in load()). */
    protected PrivateKey privateKey;

    protected PrivateKeyLoader(Path directory, String fileName) {
        this.directory = directory;
        this.fileName = fileName;
        
        System.out.println(".. loading Certificate: " + fileName + " from directory: " + directory );
    }

    /** Vollständiger Pfad zur Schlüsseldatei. */
    public Path filePath() {
        return directory.resolve(fileName);
    }

    /** Lädt den privaten Schlüssel (setzt das geschützte Feld). */
    public abstract void load() throws Exception;

    /** Getter für den privaten Schlüssel. */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    // Hilfen für Subklassen
    protected byte[] readFileBytes() throws IOException {
        return Files.readAllBytes(filePath());
    }

    protected String readFileString() throws IOException {
        return Files.readString(filePath());
    }
}
