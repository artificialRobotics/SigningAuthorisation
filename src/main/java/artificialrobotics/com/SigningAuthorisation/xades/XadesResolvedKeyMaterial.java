package artificialrobotics.com.SigningAuthorisation.xades;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class XadesResolvedKeyMaterial {

    private final PrivateKey privateKey;
    private final X509Certificate signingCertificate;
    private final List<X509Certificate> certificateChain;

    public XadesResolvedKeyMaterial(PrivateKey privateKey,
                                    X509Certificate signingCertificate,
                                    List<X509Certificate> certificateChain) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
        this.signingCertificate = Objects.requireNonNull(signingCertificate, "signingCertificate must not be null");
        this.certificateChain = List.copyOf(Objects.requireNonNull(certificateChain, "certificateChain must not be null"));

        if (this.certificateChain.isEmpty()) {
            throw new IllegalArgumentException("certificateChain must not be empty");
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public List<CertificateToken> toCertificateTokens() {
        List<CertificateToken> tokens = new ArrayList<>(certificateChain.size());
        for (X509Certificate certificate : certificateChain) {
            tokens.add(new CertificateToken(certificate));
        }
        return tokens;
    }
}