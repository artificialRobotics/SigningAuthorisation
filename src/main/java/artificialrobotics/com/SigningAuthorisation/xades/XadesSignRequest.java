package artificialrobotics.com.SigningAuthorisation.xades;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public final class XadesSignRequest {

    private final String format;
    private final String alg;
    private final Path payloadFile;
    private final Path outFile;
    private final String referenceURI;

    private final Path keyDir;
    private final String keyFile;

    private final Path keystorePath;
    private final String keystoreType;
    private final String keystorePassword;
    private final String keyAlias;
    private final String keyPassword;

    private final Path certDir;
    private final String certFile;

    private final boolean debug;

    public XadesSignRequest(String format,
                            String alg,
                            Path payloadFile,
                            Path outFile,
                            String referenceURI,
                            Path keyDir,
                            String keyFile,
                            Path keystorePath,
                            String keystoreType,
                            String keystorePassword,
                            String keyAlias,
                            String keyPassword,
                            Path certDir,
                            String certFile,
                            boolean debug) {
        this.format = format;
        this.alg = alg;
        this.payloadFile = payloadFile;
        this.outFile = outFile;
        this.referenceURI = referenceURI;
        this.keyDir = keyDir;
        this.keyFile = keyFile;
        this.keystorePath = keystorePath;
        this.keystoreType = (keystoreType == null || keystoreType.isBlank()) ? "PKCS12" : keystoreType;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
        this.certDir = certDir;
        this.certFile = certFile;
        this.debug = debug;
    }

    public void validate() {
        if (format == null || !"xades".equalsIgnoreCase(format.trim())) {
            throw new IllegalArgumentException("--format must be 'xades' for sign-xml.");
        }

        if (alg == null || alg.isBlank()) {
            throw new IllegalArgumentException("--alg is required.");
        }

        if (payloadFile == null) {
            throw new IllegalArgumentException("--payload is required.");
        }
        if (!Files.exists(payloadFile)) {
            throw new IllegalArgumentException("Payload file not found: " + payloadFile.toAbsolutePath());
        }
        if (!Files.isRegularFile(payloadFile)) {
            throw new IllegalArgumentException("Payload path is not a regular file: " + payloadFile.toAbsolutePath());
        }

        if (outFile == null) {
            throw new IllegalArgumentException("--out is required.");
        }

        Path absPayload = payloadFile.toAbsolutePath().normalize();
        Path absOut = outFile.toAbsolutePath().normalize();
        if (absPayload.equals(absOut)) {
            throw new IllegalArgumentException("For detached XAdES, --out must differ from --payload. The original XML must remain unchanged.");
        }

        if (referenceURI != null && referenceURI.isBlank()) {
            throw new IllegalArgumentException("--referenceURI must not be blank when provided.");
        }

        if (usesKeystore()) {
            if (keystorePassword == null) {
                throw new IllegalArgumentException("--keystorePassword is required when --keystore is used.");
            }
            if (keyAlias == null || keyAlias.isBlank()) {
                throw new IllegalArgumentException("--keyAlias is required when --keystore is used.");
            }
        } else {
            if (keyDir == null || keyFile == null || keyFile.isBlank()) {
                throw new IllegalArgumentException("Either provide --keystore... OR --key-dir and --key-file.");
            }
            if (certDir == null || certFile == null || certFile.isBlank()) {
                throw new IllegalArgumentException("For file-based signing, --cert-dir and --cert-file are required.");
            }
        }

        String normalizedAlg = alg.trim().toUpperCase(Locale.ROOT);
        switch (normalizedAlg) {
            case "RS256", "RS384", "RS512",
                 "PS256", "PS384", "PS512",
                 "ES256", "ES384", "ES512",
                 "RSA_SHA256", "RSA_SHA384", "RSA_SHA512",
                 "RSA_SSA_PSS_SHA256_MGF1", "RSA_SSA_PSS_SHA384_MGF1", "RSA_SSA_PSS_SHA512_MGF1",
                 "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512" -> {
                // supported
            }
            default -> throw new IllegalArgumentException("Unsupported --alg for XAdES: " + alg);
        }
    }

    public boolean usesKeystore() {
        return keystorePath != null;
    }

    public boolean hasReferenceURI() {
        return referenceURI != null && !referenceURI.isBlank();
    }

    public String getDetachedReferenceUri() {
        if (hasReferenceURI()) {
            return referenceURI;
        }
        return payloadFile.getFileName().toString();
    }

    public String getFormat() {
        return format;
    }

    public String getAlg() {
        return alg;
    }

    public Path getPayloadFile() {
        return payloadFile;
    }

    public Path getOutFile() {
        return outFile;
    }

    public String getReferenceURI() {
        return referenceURI;
    }

    public Path getKeyDir() {
        return keyDir;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public Path getKeystorePath() {
        return keystorePath;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public Path getCertDir() {
        return certDir;
    }

    public String getCertFile() {
        return certFile;
    }

    public boolean isDebug() {
        return debug;
    }

    @Override
    public String toString() {
        return "XadesSignRequest{" +
            "format='" + format + '\'' +
            ", alg='" + alg + '\'' +
            ", payloadFile=" + payloadFile +
            ", outFile=" + outFile +
            ", referenceURI='" + referenceURI + '\'' +
            ", detachedReferenceUri='" + getDetachedReferenceUri() + '\'' +
            ", usesKeystore=" + usesKeystore() +
            ", certFile=" + certFile +
            ", debug=" + debug +
            '}';
    }
}