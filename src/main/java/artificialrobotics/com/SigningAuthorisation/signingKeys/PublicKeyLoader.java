package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

/** Abstrakte Basisklasse für Public-Key-Loader (Pfad + Dateiname + Getter). */
public abstract class PublicKeyLoader {

    protected final Path directory;
    protected final String fileName;

    /** Geladener Public Key (Subklassen setzen dieses Feld in load()). */
    protected PublicKey publicKey;

    protected PublicKeyLoader(Path directory, String fileName) {
        this.directory = directory;
        this.fileName = fileName;
    }

    /** Vollständiger Pfad zur Schlüsseldatei. */
    public Path filePath() { return directory.resolve(fileName); }

    /** Lädt den öffentlichen Schlüssel (setzt das geschützte Feld). */
    public abstract void load() throws Exception;

    /** Getter für den Public Key. */
    public PublicKey getPublicKey() { return publicKey; }

    // Hilfen für Subklassen
    protected byte[] readFileBytes() throws IOException {
        return Files.readAllBytes(filePath());
    }
    protected String readFileString() throws IOException {
        return Files.readString(filePath());
    }
}
