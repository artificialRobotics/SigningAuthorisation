package artificialrobotics.com.SigningAuthorisation.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;

import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public final class XadesSignatureParametersFactory {

    public XAdESSignatureParameters create(XadesSignRequest request,
                                           XadesResolvedKeyMaterial keyMaterial,
                                           byte[] payloadBytes) {
        ResolvedXadesAlgorithm resolved = resolveAlgorithm(request.getAlg(), keyMaterial.getPrivateKey());

        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        parameters.setEncryptionAlgorithm(resolved.getEncryptionAlgorithm());
        parameters.setDigestAlgorithm(resolved.getDigestAlgorithm());

        parameters.setSigningCertificate(new CertificateToken(keyMaterial.getSigningCertificate()));
        parameters.setCertificateChain(keyMaterial.toCertificateTokens());
        parameters.setPrettyPrint(true);

        parameters.bLevel().setSigningDate(Date.from(Instant.now()));

        if (request.hasReferenceURI()) {
            parameters.setReferences(buildCustomDetachedReferences(request, payloadBytes, resolved.getDigestAlgorithm()));
        }

        return parameters;
    }

    private List<DSSReference> buildCustomDetachedReferences(XadesSignRequest request,
                                                             byte[] payloadBytes,
                                                             DigestAlgorithm digestAlgorithm) {
        DSSReference detachedReference = new DSSReference();
        detachedReference.setUri(request.getDetachedReferenceUri());
        detachedReference.setDigestMethodAlgorithm(digestAlgorithm);

        InMemoryDocument detachedContents = new InMemoryDocument(
            payloadBytes,
            request.getPayloadFile().getFileName().toString()
        );
        detachedReference.setContents(detachedContents);

        return List.of(detachedReference);
    }

    public ResolvedXadesAlgorithm resolveAlgorithm(String alg, PrivateKey privateKey) {
        if (alg == null || alg.isBlank()) {
            throw new IllegalArgumentException("Algorithm must not be blank.");
        }

        String normalized = alg.trim().toUpperCase(Locale.ROOT);
        String keyAlgorithm = privateKey.getAlgorithm().toUpperCase(Locale.ROOT);

        return switch (normalized) {
            case "RS256", "RSA_SHA256" -> {
                requireClassicRsaKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.RSA_SHA256,
                    EncryptionAlgorithm.RSA,
                    DigestAlgorithm.SHA256,
                    "SHA256withRSA",
                    null
                );
            }
            case "RS384", "RSA_SHA384" -> {
                requireClassicRsaKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.RSA_SHA384,
                    EncryptionAlgorithm.RSA,
                    DigestAlgorithm.SHA384,
                    "SHA384withRSA",
                    null
                );
            }
            case "RS512", "RSA_SHA512" -> {
                requireClassicRsaKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.RSA_SHA512,
                    EncryptionAlgorithm.RSA,
                    DigestAlgorithm.SHA512,
                    "SHA512withRSA",
                    null
                );
            }
            case "PS256", "RSA_SSA_PSS_SHA256_MGF1" -> {
                requireRsaOrPssKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
                    EncryptionAlgorithm.RSASSA_PSS,
                    DigestAlgorithm.SHA256,
                    "RSASSA-PSS",
                    new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                );
            }
            case "PS384", "RSA_SSA_PSS_SHA384_MGF1" -> {
                requireRsaOrPssKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
                    EncryptionAlgorithm.RSASSA_PSS,
                    DigestAlgorithm.SHA384,
                    "RSASSA-PSS",
                    new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
                );
            }
            case "PS512", "RSA_SSA_PSS_SHA512_MGF1" -> {
                requireRsaOrPssKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
                    EncryptionAlgorithm.RSASSA_PSS,
                    DigestAlgorithm.SHA512,
                    "RSASSA-PSS",
                    new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
                );
            }
            case "ES256", "ECDSA_SHA256" -> {
                requireEcKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.ECDSA_SHA256,
                    EncryptionAlgorithm.ECDSA,
                    DigestAlgorithm.SHA256,
                    "SHA256withECDSA",
                    null
                );
            }
            case "ES384", "ECDSA_SHA384" -> {
                requireEcKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.ECDSA_SHA384,
                    EncryptionAlgorithm.ECDSA,
                    DigestAlgorithm.SHA384,
                    "SHA384withECDSA",
                    null
                );
            }
            case "ES512", "ECDSA_SHA512" -> {
                requireEcKey(keyAlgorithm, alg);
                yield new ResolvedXadesAlgorithm(
                    SignatureAlgorithm.ECDSA_SHA512,
                    EncryptionAlgorithm.ECDSA,
                    DigestAlgorithm.SHA512,
                    "SHA512withECDSA",
                    null
                );
            }
            default -> throw new IllegalArgumentException("Unsupported XAdES algorithm: " + alg);
        };
    }

    private static void requireClassicRsaKey(String keyAlgorithm, String alg) {
        if (!"RSA".equals(keyAlgorithm)) {
            throw new IllegalArgumentException(
                "Algorithm " + alg + " requires a classic RSA private key, but got: " + keyAlgorithm
            );
        }
    }

    private static void requireRsaOrPssKey(String keyAlgorithm, String alg) {
        if (!"RSA".equals(keyAlgorithm) && !"RSASSA-PSS".equals(keyAlgorithm)) {
            throw new IllegalArgumentException(
                "Algorithm " + alg + " requires an RSA or RSASSA-PSS private key, but got: " + keyAlgorithm
            );
        }
    }

    private static void requireEcKey(String keyAlgorithm, String alg) {
        if (!"EC".equals(keyAlgorithm) && !"ECDSA".equals(keyAlgorithm)) {
            throw new IllegalArgumentException(
                "Algorithm " + alg + " requires an EC private key, but got: " + keyAlgorithm
            );
        }
    }

    public static final class ResolvedXadesAlgorithm {
        private final SignatureAlgorithm signatureAlgorithm;
        private final EncryptionAlgorithm encryptionAlgorithm;
        private final DigestAlgorithm digestAlgorithm;
        private final String jcaSignatureName;
        private final PSSParameterSpec pssParameterSpec;

        public ResolvedXadesAlgorithm(SignatureAlgorithm signatureAlgorithm,
                                      EncryptionAlgorithm encryptionAlgorithm,
                                      DigestAlgorithm digestAlgorithm,
                                      String jcaSignatureName,
                                      PSSParameterSpec pssParameterSpec) {
            this.signatureAlgorithm = signatureAlgorithm;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.digestAlgorithm = digestAlgorithm;
            this.jcaSignatureName = jcaSignatureName;
            this.pssParameterSpec = pssParameterSpec;
        }

        public SignatureAlgorithm getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public EncryptionAlgorithm getEncryptionAlgorithm() {
            return encryptionAlgorithm;
        }

        public DigestAlgorithm getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public String getJcaSignatureName() {
            return jcaSignatureName;
        }

        public PSSParameterSpec getPssParameterSpec() {
            return pssParameterSpec;
        }
    }
}