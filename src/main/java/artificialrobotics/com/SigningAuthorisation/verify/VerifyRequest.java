package artificialrobotics.com.SigningAuthorisation.verify;

import java.nio.file.Path;

public final class VerifyRequest {

    private final String mode;
    private final String alg;
    private final Path inFile;
    private final Path pubDir;
    private final String pubFile;
    private final boolean detached;
    private final Path payloadFile;
    private final Path payloadHashFile;
    private final String canonicalizePayload;
    private final Path truststorePath;
    private final String truststoreType;
    private final String truststorePassword;
    private final Path validationPolicyFile;
    private final boolean debug;

    public VerifyRequest(String mode,
                         String alg,
                         Path inFile,
                         Path pubDir,
                         String pubFile,
                         boolean detached,
                         Path payloadFile,
                         Path payloadHashFile,
                         String canonicalizePayload,
                         Path truststorePath,
                         String truststoreType,
                         String truststorePassword,
                         Path validationPolicyFile,
                         boolean debug) {
        this.mode = mode;
        this.alg = alg;
        this.inFile = inFile;
        this.pubDir = pubDir;
        this.pubFile = pubFile;
        this.detached = detached;
        this.payloadFile = payloadFile;
        this.payloadHashFile = payloadHashFile;
        this.canonicalizePayload = canonicalizePayload;
        this.truststorePath = truststorePath;
        this.truststoreType = truststoreType;
        this.truststorePassword = truststorePassword;
        this.validationPolicyFile = validationPolicyFile;
        this.debug = debug;
    }

    public String getMode() {
        return mode;
    }

    public String getAlg() {
        return alg;
    }

    public Path getInFile() {
        return inFile;
    }

    public Path getPubDir() {
        return pubDir;
    }

    public String getPubFile() {
        return pubFile;
    }

    public boolean isDetached() {
        return detached;
    }

    public Path getPayloadFile() {
        return payloadFile;
    }

    public Path getPayloadHashFile() {
        return payloadHashFile;
    }

    public String getCanonicalizePayload() {
        return canonicalizePayload;
    }

    public Path getTruststorePath() {
        return truststorePath;
    }

    public String getTruststoreType() {
        return truststoreType;
    }

    public String getTruststorePassword() {
        return truststorePassword;
    }

    public Path getValidationPolicyFile() {
        return validationPolicyFile;
    }

    public boolean isDebug() {
        return debug;
    }

    public boolean hasPayloadFile() {
        return payloadFile != null;
    }

    public boolean hasPayloadHashFile() {
        return payloadHashFile != null;
    }

    public boolean hasTruststore() {
        return truststorePath != null;
    }

    public boolean hasTruststorePassword() {
        return truststorePassword != null;
    }

    public boolean hasPublicKeyMaterial() {
        return pubDir != null && pubFile != null;
    }
}