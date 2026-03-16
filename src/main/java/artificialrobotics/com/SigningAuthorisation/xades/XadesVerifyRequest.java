package artificialrobotics.com.SigningAuthorisation.xades;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public final class XadesVerifyRequest {

    private final String format;
    private final Path signatureFile;
    private final Path payloadFile;
    private final Path truststorePath;
    private final String truststoreType;
    private final String truststorePassword;
    private final Path validationPolicyFile;
    private final boolean debug;

    public XadesVerifyRequest(String format,
                              Path signatureFile,
                              Path payloadFile,
                              Path truststorePath,
                              String truststoreType,
                              String truststorePassword,
                              Path validationPolicyFile,
                              boolean debug) {
        this.format = format;
        this.signatureFile = signatureFile;
        this.payloadFile = payloadFile;
        this.truststorePath = truststorePath;
        this.truststoreType = (truststoreType == null || truststoreType.isBlank()) ? "PKCS12" : truststoreType.trim();
        this.truststorePassword = truststorePassword;
        this.validationPolicyFile = validationPolicyFile;
        this.debug = debug;
    }

    public void validate() {
        if (format == null || !"xades".equalsIgnoreCase(format.trim())) {
            throw new IllegalArgumentException("--format must be 'xades' for verify-xml.");
        }

        if (signatureFile == null) {
            throw new IllegalArgumentException("--in is required.");
        }
        if (!Files.exists(signatureFile) || !Files.isRegularFile(signatureFile)) {
            throw new IllegalArgumentException("Signature file not found: " + signatureFile.toAbsolutePath());
        }

        if (payloadFile == null) {
            throw new IllegalArgumentException("--payload is required for detached XAdES validation.");
        }
        if (!Files.exists(payloadFile) || !Files.isRegularFile(payloadFile)) {
            throw new IllegalArgumentException("Payload file not found: " + payloadFile.toAbsolutePath());
        }

        if (truststorePath == null) {
            throw new IllegalArgumentException("--truststore is required.");
        }
        if (!Files.exists(truststorePath) || !Files.isRegularFile(truststorePath)) {
            throw new IllegalArgumentException("Truststore file not found: " + truststorePath.toAbsolutePath());
        }

        if (truststorePassword == null) {
            throw new IllegalArgumentException("--truststorePassword is required.");
        }

        String normalizedTruststoreType = truststoreType.toUpperCase(Locale.ROOT);
        if (!normalizedTruststoreType.equals("PKCS12") && !normalizedTruststoreType.equals("JKS")) {
            throw new IllegalArgumentException("Unsupported --truststoreType: " + truststoreType + " (use PKCS12 or JKS)");
        }

        if (validationPolicyFile != null && (!Files.exists(validationPolicyFile) || !Files.isRegularFile(validationPolicyFile))) {
            throw new IllegalArgumentException("Validation policy file not found: " + validationPolicyFile.toAbsolutePath());
        }
    }

    public String getFormat() {
        return format;
    }

    public Path getSignatureFile() {
        return signatureFile;
    }

    public Path getPayloadFile() {
        return payloadFile;
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

    @Override
    public String toString() {
        return "XadesVerifyRequest{" +
            "format='" + format + '\'' +
            ", signatureFile=" + signatureFile +
            ", payloadFile=" + payloadFile +
            ", truststorePath=" + truststorePath +
            ", truststoreType='" + truststoreType + '\'' +
            ", validationPolicyFile=" + validationPolicyFile +
            ", debug=" + debug +
            '}';
    }
}