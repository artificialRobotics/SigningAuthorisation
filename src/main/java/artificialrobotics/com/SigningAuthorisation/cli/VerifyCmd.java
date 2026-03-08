package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PublicKeyFactory;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import picocli.CommandLine;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

/**
 * # VerifyCmd
 *
 * Verifies JWS/JAdES signatures in two modes:
 *  - crypto: local, crypto-only verification against a provided public key/certificate
 *  - eidas : verification via DSS using truststore and validation policy
 *
 * Supported inputs:
 *  - JWS Compact Serialization (RFC 7515 §3.1)
 *  - JWS JSON Serialization (RFC 7515 §7.2; single signature object)
 *  - Berlin Group wrapper JSON (BG)
 *
 * Detached & RFC 7797:
 *  - Detached payload is supported via --payload
 *  - RFC 7797 unencoded payload ("b64": false) is supported
 *
 * Canonicalization:
 *  - Optional JCS (RFC 8785) may be applied to the detached payload before verification
 *    using --canonicalize-payload=jcs. This must match the signing process exactly.
 *
 * Algorithm resolution:
 *  - --alg=ph resolves the algorithm from the protected header claim "alg"
 *
 * ECDSA note:
 *  - Standard JWS ES* uses raw R||S encoding, which is converted to DER for JCA verification
 *  - A proprietary ES* profile may use pre-hash + NONEwithECDSA and DER signatures directly
 *  - This verifier supports both forms in crypto mode
 *
 * DSS / eIDAS profile note:
 *  - In this project, the DSS path is used to reproduce the existing hash-only verification profile.
 *  - This means: detached content supplied via --payload is treated as the payload representation
 *    to be verified by DSS, which in the ES* project flow is the hash payload, not a large original
 *    business payload.
 *  - BG wrapper JSON is transformed to plain JOSE JSON before handing it to DSS.
 *  - In DSS mode, --pub-dir / --pub-file are ignored. Trust is established via truststore.
 */
@CommandLine.Command(name = "verify", description = "Verify JWS/JAdES (crypto-only or eIDAS/DSS).")
public class VerifyCmd implements Runnable {

    @CommandLine.Option(names = "--mode", required = true, description = "crypto | eidas")
    String mode;

    @CommandLine.Option(names = "--alg", required = true, description = "RS512 | PS512 | ES256 | ES384 | ES512 | ph")
    String alg;

    @CommandLine.Option(names = "--in", required = true, description = "JWS input file (compact OR JSON serialization; BG wrapper supported).")
    Path inFile;

    // crypto mode
    @CommandLine.Option(names = "--pub-dir", description = "Directory of public key / certificate")
    Path pubDir;

    @CommandLine.Option(names = "--pub-file", description = "File name of public key / certificate")
    String pubFile;

    // detached payload / RFC 7797
    @CommandLine.Option(names = "--detached", description = "Treat input as detached JWS. Provide --payload for verification.")
    boolean detached;

    @CommandLine.Option(names = "--payload", description = "Detached payload file (raw bytes). In DSS mode this is the detached hash-payload representation used by the project profile.")
    Path payloadFile;

    @CommandLine.Option(names = "--canonicalize-payload", description = "Apply canonicalization to detached payload before verification. Supported value: jcs")
    String canonicalizePayload;

    // DSS / eIDAS mode
    @CommandLine.Option(names = "--truststore", description = "Truststore file for DSS verification (PKCS12/JKS).")
    Path truststorePath;

    @CommandLine.Option(names = "--truststoreType", description = "Truststore type: PKCS12 | JKS (default: PKCS12)")
    String truststoreType = "PKCS12";

    @CommandLine.Option(names = "--truststorePassword", description = "Truststore password for DSS verification.")
    String truststorePassword;

    @CommandLine.Option(names = "--validationPolicy", description = "Custom DSS validation policy XML file. If omitted, DSS default policy is used.")
    Path validationPolicyFile;

    @Override
    public void run() {
        try {
            new InitBC();

            final String content = Files.readString(inFile, StandardCharsets.UTF_8).trim();

            if ("eidas".equalsIgnoreCase(mode)) {
                verifyWithDss(content);
                return;
            }

            /* ====================== CRYPTO MODE ====================== */

            String protectedB64;
            String payloadB64 = null;
            String signatureB64;

            if (isJsonSerialization(content)) {
                protectedB64 = extractJsonValue(content, "\"protected\"");
                signatureB64 = extractJsonValue(content, "\"signature\"");
                if (content.contains("\"payload\"")) {
                    payloadB64 = extractJsonValue(content, "\"payload\"");
                }
            } else {
                String[] parts = content.split("\\.", -1);
                if (parts.length != 3) {
                    throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
                }
                protectedB64 = parts[0];
                payloadB64 = parts[1];
                signatureB64 = parts[2];
            }

            byte[] protectedJson = Base64.getUrlDecoder().decode(protectedB64);
            String protectedStr = new String(protectedJson, StandardCharsets.UTF_8);
            boolean b64false = protectedStr.contains("\"b64\":false");

            String resolvedAlg = alg;
            if ("ph".equalsIgnoreCase(alg)) {
                String headerAlg = extractJsonValue(protectedStr, "\"alg\"");
                if (headerAlg == null || headerAlg.isEmpty()) {
                    throw new IllegalArgumentException("Protected header does not contain an 'alg' claim.");
                }
                resolvedAlg = headerAlg;
            }

            byte[] signingInput;
            if (b64false) {
                if (payloadFile == null) {
                    throw new IllegalArgumentException("b64=false requires --payload with RAW payload bytes.");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                byte[] raw = loadDetachedPayloadPossiblyCanonicalized();
                signingInput = concat(left, raw);
            } else {
                if (detached) {
                    if (payloadFile == null) {
                        throw new IllegalArgumentException("detached requires --payload (for b64=true).");
                    }
                    byte[] raw = loadDetachedPayloadPossiblyCanonicalized();
                    payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
                } else {
                    if (payloadB64 == null) {
                        throw new IllegalArgumentException("Embedded signature expects a 'payload' in the JWS.");
                    }
                }
                signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            }

            byte[] sig = Base64.getUrlDecoder().decode(signatureB64);

            if (pubDir == null || pubFile == null) {
                throw new IllegalArgumentException("crypto mode requires --pub-dir and --pub-file (public key or certificate).");
            }

            PublicKey pub;
            try {
                pub = PublicKeyFactory.load(pubDir, pubFile);
            } catch (Exception e) {
                var cl = new PEMCertificateLoader(pubDir, pubFile);
                cl.load();
                if (cl.getCertificate() == null) {
                    throw new IllegalArgumentException("Could not load a public key (neither key nor certificate).", e);
                }
                pub = cl.getCertificate().getPublicKey();
            }

            boolean ok = verifyJws(signingInput, sig, pub, resolvedAlg);
            System.out.println("VALID (crypto-only): " + ok);
            System.out.println(ok ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== DSS / eIDAS verification ====================== */

    /**
     * Performs DSS/eIDAS validation for the project-specific detached hash profile.
     *
     * Responsibilities:
     * - transforms BG or compact JWS into JOSE JSON for DSS
     * - loads trust anchors from provided truststore
     * - configures DSS validator
     * - loads detached payload representation from --payload
     * - applies custom validation policy or DSS default policy
     * - prints a clear final result
     *
     * Important project behavior:
     * - detached content supplied via --payload is used as the payload representation
     *   that DSS validates against. In this project this can be the hash-payload representation.
     */
    private void verifyWithDss(String content) throws Exception {
        if (truststorePath == null) {
            throw new IllegalArgumentException("--truststore is required for --mode eidas.");
        }
        if (truststorePassword == null) {
            throw new IllegalArgumentException("--truststorePassword is required for --mode eidas.");
        }

        if (pubDir != null || pubFile != null) {
            System.out.println("INFO: --pub-dir / --pub-file are ignored in DSS/eIDAS mode. DSS uses truststore + validation policy.");
        }

        String jsonForDss = toJoseJsonForDss(content);

        DSSDocument sigDoc = new InMemoryDocument(
                jsonForDss.getBytes(StandardCharsets.UTF_8),
                "sig.jws",
                MimeTypeEnum.JOSE_JSON
        );

        /* ---------- TRUSTSTORE -> TRUSTED CERT SOURCE ---------- */

        KeyStore trustStore = KeyStore.getInstance(truststoreType);
        try (InputStream is = Files.newInputStream(truststorePath)) {
            trustStore.load(is, truststorePassword.toCharArray());
        }

        CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();

        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            java.security.cert.Certificate cert = trustStore.getCertificate(alias);
            if (cert instanceof X509Certificate x509) {
                trustedSource.addCertificate(new CertificateToken(x509));
            }
        }

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trustedSource);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(sigDoc);
        validator.setCertificateVerifier(verifier);

        if (payloadFile != null) {
            byte[] raw = loadDetachedPayloadPossiblyCanonicalized();
            validator.setDetachedContents(List.of(new InMemoryDocument(raw)));
            System.out.println("INFO: DSS detached content loaded from --payload. In this project profile this represents the hash-payload input.");
        } else {
            System.out.println("INFO: No detached payload provided to DSS.");
        }

        /* ---------- EXECUTE DSS VALIDATION ---------- */

        Reports reports;
        if (validationPolicyFile != null) {
            if (!Files.exists(validationPolicyFile)) {
                throw new IllegalArgumentException("Validation policy file not found: " + validationPolicyFile);
            }
            reports = validator.validateDocument(validationPolicyFile.toFile());
            System.out.println("Using custom validation policy: " + validationPolicyFile.toAbsolutePath());
        } else {
            reports = validator.validateDocument((File) null);
            System.out.println("Using DSS default validation policy.");
        }

        System.out.println("Validation process finished.");
        System.out.println("Simple report object available: " + (reports.getSimpleReport() != null));
        System.out.println("Detailed report object available: " + (reports.getDetailedReport() != null));
        System.out.println("Diagnostic data available: " + (reports.getDiagnosticData() != null));

        boolean overallValid = isDssValidationSuccessful(reports);
        System.out.println(overallValid ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
    }

    /**
     * Converts supported input variants into JOSE JSON expected by DSS.
     *
     * Supported source formats:
     * - Berlin Group wrapper JSON
     * - plain JOSE JSON serialization
     * - compact JWS serialization
     */
    private static String toJoseJsonForDss(String content) {
        if (isBerlinGroupSerialization(content)) {
            String protectedB64 = extractJsonValue(content, "\"protected\"");
            String signatureB64 = extractJsonValue(content, "\"signature\"");

            return """
            {
              "protected":"%s",
              "signature":"%s"
            }
            """.formatted(protectedB64, signatureB64).trim();
        }

        if (isPlainJoseJsonSerialization(content)) {
            return content;
        }

        String[] parts = content.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid compact JWS for DSS.");
        }

        String protectedB64 = parts[0];
        String payloadB64 = parts[1];
        String signatureB64 = parts[2];

        if (payloadB64 == null || payloadB64.isEmpty()) {
            return """
            {
              "protected":"%s",
              "signature":"%s"
            }
            """.formatted(protectedB64, signatureB64).trim();
        } else {
            return """
            {
              "payload":"%s",
              "protected":"%s",
              "signature":"%s"
            }
            """.formatted(payloadB64, protectedB64, signatureB64).trim();
        }
    }

    /**
     * Tries to determine an overall DSS validation result.
     *
     * This method intentionally avoids compile-time dependency on version-specific DSS SimpleReport APIs.
     * It uses reflection to look for typical methods such as:
     * - getSignatureIdList()
     * - isValid(String)
     * - getFirstSignatureId()
     *
     * Behavior:
     * - if no signatures are found => false
     * - if any signature is invalid => false
     * - if all detected signatures are valid => true
     * - otherwise conservative fallback => false
     */
    private static boolean isDssValidationSuccessful(Reports reports) {
        if (reports == null || reports.getSimpleReport() == null) {
            return false;
        }

        Object simpleReport = reports.getSimpleReport();

        try {
            Method getSignatureIdList = simpleReport.getClass().getMethod("getSignatureIdList");
            Object idsObj = getSignatureIdList.invoke(simpleReport);

            List<String> ids = new ArrayList<>();
            if (idsObj instanceof Iterable<?> iterable) {
                for (Object o : iterable) {
                    if (o != null) {
                        ids.add(String.valueOf(o));
                    }
                }
            }

            if (ids.isEmpty()) {
                return false;
            }

            Method isValid = simpleReport.getClass().getMethod("isValid", String.class);
            for (String id : ids) {
                Object validObj = isValid.invoke(simpleReport, id);
                if (!(validObj instanceof Boolean b) || !b) {
                    return false;
                }
            }
            return true;

        } catch (Exception ignore) {
            try {
                Method getFirstSignatureId = simpleReport.getClass().getMethod("getFirstSignatureId");
                Object firstIdObj = getFirstSignatureId.invoke(simpleReport);
                if (firstIdObj == null) {
                    return false;
                }

                Method isValid = simpleReport.getClass().getMethod("isValid", String.class);
                Object validObj = isValid.invoke(simpleReport, String.valueOf(firstIdObj));
                return (validObj instanceof Boolean b) && b;

            } catch (Exception ignoredAgain) {
                return false;
            }
        }
    }

    /* ====================== Crypto verify path ====================== */

    /**
     * Verifies a JWS signature using the selected JWA algorithm family.
     *
     * Supported:
     * - RS512
     * - PS512
     * - ES256 / ES384 / ES512
     *
     * For ECDSA both standard raw R||S and proprietary DER + pre-hash variants are supported.
     */
    private static boolean verifyJws(byte[] signingInput, byte[] sig, PublicKey pub, String alg) throws Exception {
        switch (alg) {
            case "RS512": {
                Signature v = Signature.getInstance("SHA512withRSA");
                v.initVerify(pub);
                v.update(signingInput);
                return v.verify(sig);
            }
            case "PS512": {
                Signature v = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"),
                        64, 1);
                v.setParameter(pss);
                v.initVerify(pub);
                v.update(signingInput);
                return v.verify(sig);
            }
            case "ES256":
            case "ES384":
            case "ES512": {
                int fieldSize = ecdsaFieldSizeBytes(alg);
                int expectedRawLen = 2 * fieldSize;

                boolean looksLikeRawConcat = (sig.length == expectedRawLen);
                boolean looksLikeDer = (sig.length > 0 && sig[0] == 0x30);

                if (looksLikeRawConcat) {
                    String jca = switch (alg) {
                        case "ES256" -> "SHA256withECDSA";
                        case "ES384" -> "SHA384withECDSA";
                        default -> "SHA512withECDSA";
                    };
                    Signature v = Signature.getInstance(jca);
                    v.initVerify(pub);
                    v.update(signingInput);
                    byte[] der = concatToDer(sig, fieldSize);
                    return v.verify(der);
                }

                if (looksLikeDer) {
                    byte[] digest = MessageDigest.getInstance(digestAlgForEsFamily(alg)).digest(signingInput);
                    Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                    v.initVerify(pub);
                    v.update(digest);
                    return v.verify(sig);
                }

                throw new IllegalArgumentException("Unsupported ECDSA signature encoding (neither raw R||S nor DER).");
            }
            default:
                throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
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
            case "ES512" -> 66; // P-521
            default -> throw new IllegalArgumentException("Unknown ECDSA alg: " + alg);
        };
    }

    /* ====================== Helpers ====================== */

    /**
     * Heuristic: JSON input containing protected + signature.
     * Includes plain JOSE JSON and Berlin Group wrapper JSON.
     */
    private static boolean isJsonSerialization(String s) {
        return s.contains("\"protected\"") && s.contains("\"signature\"");
    }

    /**
     * Detect Berlin Group wrapper JSON:
     * {
     *   "signatureData": {
     *     "protected": "...",
     *     "signature": "..."
     *   }
     * }
     */
    private static boolean isBerlinGroupSerialization(String s) {
        return s.contains("\"signatureData\"")
                && s.contains("\"protected\"")
                && s.contains("\"signature\"");
    }

    /**
     * Detect plain JOSE JSON serialization and exclude BG wrapper JSON.
     */
    private static boolean isPlainJoseJsonSerialization(String s) {
        return s.contains("\"protected\"")
                && s.contains("\"signature\"")
                && !s.contains("\"signatureData\"");
    }

    /**
     * Minimal extraction of a simple JSON string field:
     * "key":"value"
     *
     * Sufficient for current JOSE/BG structures in this project.
     */
    private static String extractJsonValue(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) throw new IllegalArgumentException("Missing JSON field " + keyWithQuotes);
        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon + 1);
        int q2 = json.indexOf('"', q1 + 1);
        if (colon < 0 || q1 < 0 || q2 < 0) {
            throw new IllegalArgumentException("Malformed JSON near " + keyWithQuotes);
        }
        return json.substring(q1 + 1, q2);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * Loads detached payload and optionally applies JCS canonicalization.
     * This must match the signing procedure exactly.
     */
    private byte[] loadDetachedPayloadPossiblyCanonicalized() throws Exception {
        byte[] raw = Files.readAllBytes(payloadFile);
        boolean doCanonicalize = canonicalizePayload != null && canonicalizePayload.equalsIgnoreCase("jcs");
        if (!doCanonicalize) return raw;

        String asText = new String(raw, StandardCharsets.UTF_8);
        if (!looksLikeJson(asText)) {
            throw new IllegalArgumentException("--canonicalize-payload=jcs requires a JSON payload file (object or array).");
        }
        String canonical = JsonCanonicalizerJcs.canonicalize(asText);
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    private static boolean looksLikeJson(String s) {
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) i++;
        if (i >= n) return false;
        char c = s.charAt(i);
        return c == '{' || c == '[';
    }

    /**
     * Converts JWS ECDSA raw R||S into DER SEQUENCE.
     */
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
}