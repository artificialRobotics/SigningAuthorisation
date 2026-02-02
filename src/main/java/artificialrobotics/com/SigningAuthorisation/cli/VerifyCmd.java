package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;
import artificialrobotics.com.SigningAuthorisation.jose.EcdsaDer;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PublicKeyFactory;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.List;

/**
 * # VerifyCmd
 *
 * Verifies JWS/JAdES signatures in two modes:
 *  - **crypto**: local, crypto-only verification against a provided public key/certificate.
 *  - **eidas** : verification via DSS (ETSI TS 119 102/119 182 world), enabling trust services, revocation, etc.
 *
 * Supported inputs:
 *  - **JWS Compact Serialization** (RFC 7515 §3.1)
 *  - **JWS JSON Serialization** (RFC 7515 §7.2; single signature object)
 *  - **Berlin Group wrapper** (domain JSON with `signatureData.protected`/`signatureData.signature`)
 *
 * Detached & RFC 7797:
 *  - **Detached payload** supported. Provide `--payload` with the original bytes.
 *  - **Unencoded payload** (`"b64": false`, RFC 7797) supported. Requires raw payload bytes and
 *    the signing input must be built as `ASCII(Base64URL(protected) + ".") || RAW(payload)`.
 *
 * Canonicalization:
 *  - Optional **JCS** (RFC 8785) can be applied to the *external* detached payload before verification
 *    using `--canonicalize-payload=jcs` (must be valid JSON object/array). This must match the signer’s process.
 *
 * Algorithm resolution:
 *  - `--alg=ph` reads the `alg` from the **protected header** (RFC 7515 §4).
 *
 * NOTE on ECDSA:
 *  - Standard JWS ES* uses raw R||S encoding, which is transcoded to DER for JCA verification.
 *  - A proprietary ES* profile may use pre-hash + NONEwithECDSA and emit DER signatures directly.
 *    This verifier supports both by detecting the signature format.
 */
@CommandLine.Command(name = "verify", description = "Verify JWS/JAdES (crypto-only or eIDAS/DSS).")
public class VerifyCmd implements Runnable {

    @CommandLine.Option(names = "--mode", required = true, description = "crypto | eidas")
    String mode;

    @CommandLine.Option(names = "--alg", required = true, description = "RS512 | PS512 | ES256 | ES384 | ES512 | ph")
    String alg;

    @CommandLine.Option(names = "--in", required = true, description = "JWS input file (compact OR JSON serialization; BG wrapper supported).")
    Path inFile;

    @CommandLine.Option(names = "--pub-dir", description = "Directory of public key / certificate")
    Path pubDir;
    @CommandLine.Option(names = "--pub-file", description = "File name of public key / certificate")
    String pubFile;

    @CommandLine.Option(names = "--detached", description = "Treat input as detached JWS. Provide --payload for verification.")
    boolean detached;
    @CommandLine.Option(names = "--payload", description = "Detached payload file (raw bytes). Required for detached or b64=false.")
    Path payloadFile;

    @CommandLine.Option(names = "--canonicalize-payload", description = "Apply canonicalization to detached payload before verification. Supported value: jcs")
    String canonicalizePayload; // expected "jcs"

    @Override
    public void run() {
        try {
            new InitBC();

            final String content = Files.readString(inFile, StandardCharsets.UTF_8).trim();

            if ("eidas".equalsIgnoreCase(mode)) {
                verifyWithDss(content);
                return;
            }

            // === Crypto-only path ====================================================
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
                if (parts.length != 3) throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
                protectedB64 = parts[0];
                payloadB64   = parts[1];
                signatureB64 = parts[2];
            }

            byte[] protectedJson = Base64.getUrlDecoder().decode(protectedB64);
            String protectedStr  = new String(protectedJson, StandardCharsets.UTF_8);
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
                byte[] raw  = loadDetachedPayloadPossiblyCanonicalized();
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

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== DSS / eIDAS verification ====================== */

    private void verifyWithDss(String content) throws Exception {
        String jsonForDss = content;

        if (!isJsonSerialization(content)) {
            String[] parts = content.split("\\.", -1);
            if (parts.length != 3) throw new IllegalArgumentException("Invalid compact JWS for DSS.");
            String protectedB64 = parts[0];
            String payloadB64   = parts[1];
            String signatureB64 = parts[2];

            if (payloadB64 == null || payloadB64.isEmpty()) {
                jsonForDss = """
                {
                  "protected":"%s",
                  "signature":"%s"
                }
                """.formatted(protectedB64, signatureB64).trim();
            } else {
                jsonForDss = """
                {
                  "payload":"%s",
                  "protected":"%s",
                  "signature":"%s"
                }
                """.formatted(payloadB64, protectedB64, signatureB64).trim();
            }
        }

        DSSDocument sigDoc = new InMemoryDocument(jsonForDss.getBytes(StandardCharsets.UTF_8),
                                                  "sig.jws", MimeTypeEnum.JOSE_JSON);
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(sigDoc);
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        if (payloadFile != null) {
            byte[] raw = Files.readAllBytes(payloadFile);
            validator.setDetachedContents(List.of(new InMemoryDocument(raw)));
        }

        Reports reports = validator.validateDocument();
        System.out.println("VALID (DSS): " + reports.getSimpleReport().isValid("Zu ergaenzen"));
        System.out.println(reports.getSimpleReport().toString());
    }

    /* ====================== Crypto verify path ====================== */

    /**
     * Verifies a JWS signature with the given algorithm.
     *
     * - RS512: "SHA512withRSA"
     * - PS512: "RSASSA-PSS" with SHA-512 / MGF1(SHA-512) / saltLen=64
     * - ES*  : Supports both:
     *          (a) Standard JWS ES* raw R||S (transcoded to DER, verified over signingInput)
     *          (b) Proprietary ES* pre-hash + NONEwithECDSA (DER signature, verified over HASH(signingInput))
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

                // Detect signature format:
                // - Standard JWS: raw R||S with fixed length (2*fieldSize)
                // - Proprietary: DER-encoded signature (usually starts with 0x30 and has variable length)
                boolean looksLikeRawConcat = (sig.length == expectedRawLen);
                boolean looksLikeDer = (sig.length > 0 && (sig[0] == 0x30));

                if (looksLikeRawConcat) {
                    // (a) Standard JWS ES*: verify over signingInput, transcode raw->DER for JCA
                    String jca = switch (alg) {
                        case "ES256" -> "SHA256withECDSA";
                        case "ES384" -> "SHA384withECDSA";
                        default -> "SHA512withECDSA";
                    };
                    Signature v = Signature.getInstance(jca);
                    v.initVerify(pub);
                    v.update(signingInput);
                    byte[] der = EcdsaDer.transcodeConcatToDer(sig, fieldSize);
                    return v.verify(der);
                }

                if (looksLikeDer) {
                    // (b) Proprietary ES*: verify DER signature with NONEwithECDSA over HASH(signingInput)
                    byte[] digest = MessageDigest.getInstance(digestAlgForEsFamily(alg)).digest(signingInput);
                    Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                    v.initVerify(pub);
                    v.update(digest);
                    return v.verify(sig); // DER as-is
                }

                // Neither expected raw length nor DER-looking
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

    /** ECDSA field sizes in bytes for raw R||S (RFC 7518): P-256=32, P-384=48, P-521≈66. */
    private static int ecdsaFieldSizeBytes(String alg) {
        return switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512" -> 66;
            default -> throw new IllegalArgumentException("Unknown ECDSA alg: " + alg);
        };
    }

    /* ====================== Helpers ====================== */

    private static boolean isJsonSerialization(String s) {
        return s.contains("\"protected\"") && s.contains("\"signature\"");
    }

    private static String extractJsonValue(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) throw new IllegalArgumentException("Missing JSON field " + keyWithQuotes);
        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon + 1);
        int q2 = json.indexOf('"', q1 + 1);
        if (colon < 0 || q1 < 0 || q2 < 0) throw new IllegalArgumentException("Malformed JSON near " + keyWithQuotes);
        return json.substring(q1 + 1, q2);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

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
}
