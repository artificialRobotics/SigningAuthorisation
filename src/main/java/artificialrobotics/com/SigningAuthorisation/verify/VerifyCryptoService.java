package artificialrobotics.com.SigningAuthorisation.verify;

import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.jose.JoseInputParser;
import artificialrobotics.com.SigningAuthorisation.jose.ParsedJws;
import artificialrobotics.com.SigningAuthorisation.cli.PayloadInputData;
import artificialrobotics.com.SigningAuthorisation.cli.PayloadInputResolver;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PublicKeyFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

public final class VerifyCryptoService {

    private final PayloadInputResolver payloadInputResolver;
    private final VerifyDebugSupport debugSupport;

    public VerifyCryptoService(PayloadInputResolver payloadInputResolver, VerifyDebugSupport debugSupport) {
        this.payloadInputResolver = payloadInputResolver;
        this.debugSupport = debugSupport;
    }

    public boolean verifyCrypto(String content, VerifyRequest request) throws Exception {
        if (request.getPayloadFile() != null && request.getPayloadHashFile() != null) {
            throw new IllegalArgumentException("In crypto or mixed mode, use either --payload OR --payloadHashFile, not both.");
        }

        ParsedJws parsed = JoseInputParser.parse(content);

        String protectedB64 = parsed.getProtectedB64();
        String payloadB64 = parsed.getPayloadB64();
        String signatureB64 = parsed.getSignatureB64();

        byte[] protectedJson = Base64.getUrlDecoder().decode(protectedB64);
        String protectedStr = new String(protectedJson, StandardCharsets.UTF_8);
        boolean b64false = protectedStr.contains("\"b64\":false");

        String resolvedAlg = request.getAlg();
        if ("ph".equalsIgnoreCase(request.getAlg())) {
            String headerAlg = JoseInputParser.extractJsonValue(protectedStr, "\"alg\"");
            if (headerAlg == null || headerAlg.isEmpty()) {
                throw new IllegalArgumentException("Protected header does not contain an 'alg' claim.");
            }
            resolvedAlg = headerAlg;
        }

        byte[] sig = Base64.getUrlDecoder().decode(signatureB64);

        debugSupport.debug("crypto alg (requested)", request.getAlg());
        debugSupport.debug("crypto alg (resolved)", resolvedAlg);
        debugSupport.debug("crypto detached", String.valueOf(request.isDetached()));
        debugSupport.debug("crypto b64=false", String.valueOf(b64false));
        debugSupport.debug("crypto protected.b64url", protectedB64);
        debugSupport.debugMultiline("crypto protected.json", protectedStr);
        debugSupport.debug("crypto signature bytes", String.valueOf(sig.length));
        debugSupport.debug("crypto signature b64url prefix", debugSupport.abbreviate(signatureB64, 120));
        debugSupport.debug("installed providers", debugSupport.providerList());

        X509Certificate externalCert = null;
        PublicKey pub;
        try {
            pub = PublicKeyFactory.load(request.getPubDir(), request.getPubFile());
            debugSupport.debug("crypto public key source", "PublicKeyFactory");
        } catch (Exception e) {
            PEMCertificateLoader cl = new PEMCertificateLoader(request.getPubDir(), request.getPubFile());
            cl.load();
            if (cl.getCertificate() == null) {
                throw new IllegalArgumentException("Could not load a public key (neither key nor certificate).", e);
            }
            externalCert = cl.getCertificate();
            pub = externalCert.getPublicKey();
            debugSupport.debug("crypto public key source", "certificate");
        }

        debugSupport.debug("crypto public key algorithm", pub.getAlgorithm());

        X509Certificate x5cLeaf = tryExtractLeafCertificateFromProtectedJson(protectedStr);
        if (externalCert != null) {
            debugSupport.debugCertificate("external cert (--pub-file)", externalCert);
        } else {
            debugSupport.debug("external cert (--pub-file)", "not available as certificate object");
        }

        if (x5cLeaf != null) {
            debugSupport.debugCertificate("x5c[0] cert", x5cLeaf);
        } else {
            debugSupport.debug("x5c[0] cert", "not present in protected header");
        }

        if (externalCert != null && x5cLeaf != null) {
            debugSupport.debug("pub-file cert equals x5c cert", String.valueOf(externalCert.equals(x5cLeaf)));
            debugSupport.debug("pub-file public key equals x5c public key",
                    String.valueOf(MessageDigest.isEqual(
                            externalCert.getPublicKey().getEncoded(),
                            x5cLeaf.getPublicKey().getEncoded())));
        }

        if (request.getPayloadHashFile() != null) {
            byte[] providedDigest = payloadInputResolver.loadPayloadHash(request.getPayloadHashFile(), resolvedAlg);
            debugSupport.debug("crypto mode detail", "using --payloadHashFile");
            debugSupport.debug("crypto provided digest bytes", String.valueOf(providedDigest.length));
            debugSupport.debug("crypto provided digest b64", Base64.getEncoder().encodeToString(providedDigest));
            if ("RS512".equals(resolvedAlg)) {
                debugSupport.debugRs512RecoveredDigest(pub, sig, null, providedDigest, null, null, protectedStr);
            }
            return verifyJwsUsingProvidedDigest(providedDigest, sig, pub, resolvedAlg);
        }

        byte[] signingInput;
        byte[] detachedRaw = null;

        if (b64false) {
            if (request.getPayloadFile() == null) {
                throw new IllegalArgumentException("b64=false requires --payload with RAW payload bytes.");
            }
            byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
            PayloadInputData payloadData = payloadInputResolver.loadDetachedPayload(
                    request.getPayloadFile(),
                    request.getCanonicalizePayload()
            );
            byte[] raw = payloadData.getBytes();
            detachedRaw = raw;
            debugSupport.debugPayload(raw, "crypto raw payload");
            debugSupport.debugRawPayloadStructure(raw, "crypto raw payload");
            debugSupport.debugSigDHashComparisons(protectedStr, raw, "crypto raw payload");
            signingInput = concat(left, raw);
        } else {
            if (request.isDetached()) {
                if (request.getPayloadFile() == null) {
                    throw new IllegalArgumentException("detached requires --payload (for b64=true).");
                }
                PayloadInputData payloadData = payloadInputResolver.loadDetachedPayload(
                        request.getPayloadFile(),
                        request.getCanonicalizePayload()
                );
                byte[] raw = payloadData.getBytes();
                detachedRaw = raw;
                debugSupport.debugPayload(raw, "crypto detached payload");
                debugSupport.debugRawPayloadStructure(raw, "crypto detached payload");
                debugSupport.debugSigDHashComparisons(protectedStr, raw, "crypto detached payload");
                payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            } else {
                if (payloadB64 == null) {
                    throw new IllegalArgumentException("Embedded signature expects a 'payload' in the JWS.");
                }
                debugSupport.debug("crypto embedded payload b64url", debugSupport.abbreviate(payloadB64, 160));
            }
            signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            debugSupport.debug("crypto payloadB64", debugSupport.abbreviate(payloadB64, 160));
        }

        debugSupport.debug("crypto signingInput bytes", String.valueOf(signingInput.length));
        debugSupport.debug("crypto signingInput sha512 b64", sha512Base64(signingInput));
        debugSupport.debug("crypto signingInput preview", debugSupport.abbreviate(new String(signingInput, StandardCharsets.US_ASCII), 180));

        if ("RS512".equals(resolvedAlg)) {
            debugSupport.debugRs512RecoveredDigest(pub, sig, signingInput, null, detachedRaw, payloadB64, protectedStr);
        }

        return verifyJws(signingInput, sig, pub, resolvedAlg);
    }

    private boolean verifyJwsUsingProvidedDigest(byte[] providedDigest, byte[] sig, PublicKey pub, String alg) throws Exception {
        return switch (alg) {
            case "RS512" -> verifyRs512WithProvidedDigest(providedDigest, sig, pub);
            case "PS512" -> verifyPs512WithProvidedDigest(providedDigest, sig, pub);
            case "ES256", "ES384", "ES512" -> verifyEsWithProvidedDigest(providedDigest, sig, pub, alg);
            default -> throw new IllegalArgumentException("Unsupported alg for --payloadHashFile: " + alg);
        };
    }

    private boolean verifyJws(byte[] signingInput, byte[] sig, PublicKey pub, String alg) throws Exception {
        return switch (alg) {
            case "RS512" -> verifyRs512Standard(signingInput, sig, pub);
            case "PS512" -> verifyPs512Standard(signingInput, sig, pub);
            case "ES256", "ES384", "ES512" -> verifyEsStandard(signingInput, sig, pub, alg);
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };
    }

    private boolean verifyRs512Standard(byte[] signingInput, byte[] sig, PublicKey pub) throws Exception {
        Boolean result = tryVerifyWithSignature("RS512 default", "SHA512withRSA", null, null, pub, signingInput, sig);
        if (Boolean.TRUE.equals(result)) return true;

        result = tryVerifyWithSignature("RS512 BC", "SHA512withRSA", "BC", null, pub, signingInput, sig);
        return Boolean.TRUE.equals(result);
    }

    private boolean verifyPs512Standard(byte[] signingInput, byte[] sig, PublicKey pub) throws Exception {
        PSSParameterSpec pss = new PSSParameterSpec(
                "SHA-512", "MGF1",
                new java.security.spec.MGF1ParameterSpec("SHA-512"),
                64, 1
        );

        Boolean result = tryVerifyWithSignature("PS512 default RSASSA-PSS", "RSASSA-PSS", null, pss, pub, signingInput, sig);
        if (Boolean.TRUE.equals(result)) return true;

        result = tryVerifyWithSignature("PS512 BC RSASSA-PSS", "RSASSA-PSS", "BC", pss, pub, signingInput, sig);
        if (Boolean.TRUE.equals(result)) return true;

        result = tryVerifyWithSignature("PS512 BC SHA512withRSAandMGF1", "SHA512withRSAandMGF1", "BC", null, pub, signingInput, sig);
        return Boolean.TRUE.equals(result);
    }

    private boolean verifyEsStandard(byte[] signingInput, byte[] sig, PublicKey pub, String alg) throws Exception {
        int fieldSize = ecdsaFieldSizeBytes(alg);
        int expectedRawLen = 2 * fieldSize;

        boolean looksLikeRawConcat = (sig.length == expectedRawLen);
        boolean looksLikeDer = (sig.length > 0 && sig[0] == 0x30);

        debugSupport.debug("es standard looksLikeRawConcat", String.valueOf(looksLikeRawConcat));
        debugSupport.debug("es standard looksLikeDer", String.valueOf(looksLikeDer));

        if (looksLikeRawConcat) {
            String jca = switch (alg) {
                case "ES256" -> "SHA256withECDSA";
                case "ES384" -> "SHA384withECDSA";
                default -> "SHA512withECDSA";
            };
            byte[] der = concatToDer(sig, fieldSize);

            Boolean result = tryVerifyWithSignature("ES standard default raw->DER", jca, null, null, pub, signingInput, der);
            if (Boolean.TRUE.equals(result)) return true;

            result = tryVerifyWithSignature("ES standard BC raw->DER", jca, "BC", null, pub, signingInput, der);
            return Boolean.TRUE.equals(result);
        }

        if (looksLikeDer) {
            byte[] digest = MessageDigest.getInstance(digestAlgForEsFamily(alg)).digest(signingInput);

            Boolean result = tryVerifyWithSignature("ES prehash BC DER", "NONEwithECDSA", "BC", null, pub, digest, sig);
            if (Boolean.TRUE.equals(result)) return true;

            result = tryVerifyWithSignature("ES prehash default DER", "NONEwithECDSA", null, null, pub, digest, sig);
            return Boolean.TRUE.equals(result);
        }

        throw new IllegalArgumentException("Unsupported ECDSA signature encoding (neither raw R||S nor DER).");
    }

    private boolean verifyRs512WithProvidedDigest(byte[] providedDigest, byte[] sig, PublicKey pub) throws Exception {
        byte[] digestInfo = wrapSha512DigestInfo(providedDigest);

        Boolean result = tryVerifyWithSignature("RS512 digest BC NONEwithRSA", "NONEwithRSA", "BC", null, pub, digestInfo, sig);
        if (Boolean.TRUE.equals(result)) return true;

        result = tryVerifyWithSignature("RS512 digest default NONEwithRSA", "NONEwithRSA", null, null, pub, digestInfo, sig);
        return Boolean.TRUE.equals(result);
    }

    private boolean verifyPs512WithProvidedDigest(byte[] providedDigest, byte[] sig, PublicKey pub) throws Exception {
        PSSParameterSpec pss = new PSSParameterSpec(
                "SHA-512", "MGF1",
                new java.security.spec.MGF1ParameterSpec("SHA-512"),
                64, 1
        );

        Boolean result = tryVerifyWithSignature("PS512 digest BC RAWRSASSA-PSS", "RAWRSASSA-PSS", "BC", pss, pub, providedDigest, sig);
        if (Boolean.TRUE.equals(result)) return true;

        result = tryVerifyWithSignature("PS512 digest default RAWRSASSA-PSS", "RAWRSASSA-PSS", null, pss, pub, providedDigest, sig);
        return Boolean.TRUE.equals(result);
    }

    private boolean verifyEsWithProvidedDigest(byte[] providedDigest, byte[] sig, PublicKey pub, String alg) throws Exception {
        int fieldSize = ecdsaFieldSizeBytes(alg);
        boolean looksLikeRawConcat = (sig.length == 2 * fieldSize);
        boolean looksLikeDer = (sig.length > 0 && sig[0] == 0x30);

        debugSupport.debug("es digest looksLikeRawConcat", String.valueOf(looksLikeRawConcat));
        debugSupport.debug("es digest looksLikeDer", String.valueOf(looksLikeDer));

        if (looksLikeRawConcat) {
            byte[] der = concatToDer(sig, fieldSize);

            Boolean result = tryVerifyWithSignature("ES digest BC raw->DER", "NONEwithECDSA", "BC", null, pub, providedDigest, der);
            if (Boolean.TRUE.equals(result)) return true;

            result = tryVerifyWithSignature("ES digest default raw->DER", "NONEwithECDSA", null, null, pub, providedDigest, der);
            return Boolean.TRUE.equals(result);
        }

        if (looksLikeDer) {
            Boolean result = tryVerifyWithSignature("ES digest BC DER", "NONEwithECDSA", "BC", null, pub, providedDigest, sig);
            if (Boolean.TRUE.equals(result)) return true;

            result = tryVerifyWithSignature("ES digest default DER", "NONEwithECDSA", null, null, pub, providedDigest, sig);
            return Boolean.TRUE.equals(result);
        }

        throw new IllegalArgumentException("Unsupported ECDSA signature encoding (neither raw R||S nor DER).");
    }

    private Boolean tryVerifyWithSignature(String label,
                                           String algorithm,
                                           String provider,
                                           PSSParameterSpec pss,
                                           PublicKey pub,
                                           byte[] data,
                                           byte[] sig) {
        try {
            Signature verifier = (provider == null || provider.isBlank())
                    ? Signature.getInstance(algorithm)
                    : Signature.getInstance(algorithm, provider);

            if (pss != null) {
                verifier.setParameter(pss);
            }

            verifier.initVerify(pub);
            verifier.update(data);
            boolean ok = verifier.verify(sig);

            String providerName = verifier.getProvider() != null ? verifier.getProvider().getName() : "n/a";
            debugSupport.debug("verify attempt", label + " | alg=" + algorithm + " | provider=" + providerName + " | result=" + ok);
            return ok;
        } catch (Exception e) {
            debugSupport.debug("verify attempt", label + " | alg=" + algorithm + " | provider=" + (provider == null ? "<default>" : provider)
                    + " | exception=" + e.getClass().getSimpleName() + ": " + e.getMessage());
            return null;
        }
    }

    private X509Certificate tryExtractLeafCertificateFromProtectedJson(String protectedJson) {
        try {
            String leafCertDerB64 = JoseInputParser.extractFirstStringFromJsonArray(protectedJson, "\"x5c\"");
            if (leafCertDerB64 == null) {
                return null;
            }
            byte[] certDer = Base64.getDecoder().decode(leafCertDerB64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));
        } catch (Exception e) {
            debugSupport.debug("x5c extraction error", e.getMessage());
            return null;
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String digestAlgForEsFamily(String alg) {
        return switch (alg) {
            case "ES256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            case "ES512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported ES alg: " + alg);
        };
    }

    private static int ecdsaFieldSizeBytes(String alg) {
        return switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512" -> 66;
            default -> throw new IllegalArgumentException("Unknown ECDSA alg: " + alg);
        };
    }

    private static byte[] wrapSha512DigestInfo(byte[] digest) {
        if (digest == null || digest.length != 64) {
            throw new IllegalArgumentException("SHA-512 digest must be 64 bytes.");
        }
        byte[] prefix = new byte[]{
                0x30, 0x51,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                0x05, 0x00,
                0x04, 0x40
        };
        byte[] out = new byte[prefix.length + digest.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(digest, 0, out, prefix.length, digest.length);
        return out;
    }

    private static byte[] concatToDer(byte[] jwsSignature, int fieldSizeBytes) {
        if (jwsSignature == null || jwsSignature.length != fieldSizeBytes * 2) {
            throw new IllegalArgumentException("Invalid JWS ECDSA signature length.");
        }

        byte[] r = new byte[fieldSizeBytes];
        byte[] s = new byte[fieldSizeBytes];
        System.arraycopy(jwsSignature, 0, r, 0, fieldSizeBytes);
        System.arraycopy(jwsSignature, fieldSizeBytes, s, 0, fieldSizeBytes);

        byte[] rDer = unsignedIntegerToDer(r);
        byte[] sDer = unsignedIntegerToDer(s);

        int seqLen = rDer.length + sDer.length;
        byte[] seqLenEnc = derLength(seqLen);

        byte[] out = new byte[1 + seqLenEnc.length + seqLen];
        int pos = 0;
        out[pos++] = 0x30;
        System.arraycopy(seqLenEnc, 0, out, pos, seqLenEnc.length);
        pos += seqLenEnc.length;
        System.arraycopy(rDer, 0, out, pos, rDer.length);
        pos += rDer.length;
        System.arraycopy(sDer, 0, out, pos, sDer.length);

        return out;
    }

    private static byte[] unsignedIntegerToDer(byte[] value) {
        int firstNonZero = 0;
        while (firstNonZero < value.length - 1 && value[firstNonZero] == 0) {
            firstNonZero++;
        }

        int len = value.length - firstNonZero;
        boolean needsLeadingZero = (value[firstNonZero] & 0x80) != 0;

        int contentLen = len + (needsLeadingZero ? 1 : 0);
        byte[] lenEnc = derLength(contentLen);

        byte[] out = new byte[1 + lenEnc.length + contentLen];
        int pos = 0;
        out[pos++] = 0x02;
        System.arraycopy(lenEnc, 0, out, pos, lenEnc.length);
        pos += lenEnc.length;

        if (needsLeadingZero) {
            out[pos++] = 0x00;
        }

        System.arraycopy(value, firstNonZero, out, pos, len);
        return out;
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        }

        int temp = length;
        int numBytes = 0;
        while (temp > 0) {
            numBytes++;
            temp >>= 8;
        }

        byte[] out = new byte[1 + numBytes];
        out[0] = (byte) (0x80 | numBytes);

        for (int i = numBytes; i > 0; i--) {
            out[i] = (byte) (length & 0xFF);
            length >>= 8;
        }

        return out;
    }

    private static String sha512Base64(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }
}