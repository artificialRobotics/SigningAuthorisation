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
 */
@CommandLine.Command(name = "verify", description = "Verify JWS/JAdES (crypto-only or eIDAS/DSS).")
public class VerifyCmd implements Runnable {

    // Mode selection: local crypto vs DSS-based validation
    @CommandLine.Option(names = "--mode", required = true, description = "crypto | eidas")
    String mode;

    // Algorithm: explicit (RS512|PS512|ES256|ES384|ES512) or resolve from Protected Header (ph)
    @CommandLine.Option(names = "--alg", required = true, description = "RS512 | PS512 | ES256 | ES384 | ES512 | ph")
    String alg;

    // Input JWS (Compact or JSON; BG wrapper is also recognized)
    @CommandLine.Option(names = "--in", required = true, description = "JWS input file (compact OR JSON serialization; BG wrapper supported).")
    Path inFile;

    // Public key material for crypto-only mode
    @CommandLine.Option(names = "--pub-dir", description = "Directory of public key / certificate")
    Path pubDir;
    @CommandLine.Option(names = "--pub-file", description = "File name of public key / certificate")
    String pubFile;

    // Detached / RFC 7797 support
    @CommandLine.Option(names = "--detached", description = "Treat input as detached JWS. Provide --payload for verification.")
    boolean detached;
    @CommandLine.Option(names = "--payload", description = "Detached payload file (raw bytes). Required for detached or b64=false.")
    Path payloadFile;

    // Optional canonicalization for *external* payload (must match signer)
    @CommandLine.Option(names = "--canonicalize-payload", description = "Apply canonicalization to detached payload before verification. Supported value: jcs")
    String canonicalizePayload; // expected "jcs"

    @Override
    public void run() {
        try {
            // Initialize crypto providers (e.g., BouncyCastle) as per project setup
            new InitBC();

            final String content = Files.readString(inFile, StandardCharsets.UTF_8).trim();

            // === DSS / eIDAS path (uses eu.europa.esig.dss) =========================
            // Converts Compact to minimal JSON, passes detached content if provided,
            // and lets DSS perform policy-based validation (ETSI TS 119 102/182).
            if ("eidas".equalsIgnoreCase(mode)) {
                verifyWithDss(content);
                return;
            }

            // === Crypto-only path ====================================================
            // 1) Parse Compact vs JSON/BG input into protected/payload/signature fields.
            String protectedB64;
            String payloadB64 = null; // may be empty/null (detached)
            String signatureB64;

            if (isJsonSerialization(content)) {
                // JSON or BG wrapper: extract "protected" and "signature".
                // Payload may be absent for detached signatures.
                protectedB64 = extractJsonValue(content, "\"protected\"");
                signatureB64 = extractJsonValue(content, "\"signature\"");
                if (content.contains("\"payload\"")) {
                    payloadB64 = extractJsonValue(content, "\"payload\"");
                }
            } else {
                // Compact Serialization (RFC 7515 §3.1): "protected.payload.signature"
                String[] parts = content.split("\\.", -1); // keep empty parts
                if (parts.length != 3) throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
                protectedB64 = parts[0];
                payloadB64   = parts[1]; // may be empty for detached
                signatureB64 = parts[2];
            }

            // 2) Decode Protected Header JSON to detect b64=false (RFC 7797) and resolve alg if needed.
            byte[] protectedJson = Base64.getUrlDecoder().decode(protectedB64);
            String protectedStr  = new String(protectedJson, StandardCharsets.UTF_8);
            boolean b64false = protectedStr.contains("\"b64\":false");

            // If --alg=ph: read the header's alg (RFC 7515 §4)
            String resolvedAlg = alg;
            if ("ph".equalsIgnoreCase(alg)) {
                String headerAlg = extractJsonValue(protectedStr, "\"alg\"");
                if (headerAlg == null || headerAlg.isEmpty()) {
                    throw new IllegalArgumentException("Protected header does not contain an 'alg' claim.");
                }
                resolvedAlg = headerAlg;
            }

            // 3) Build the JWS signing input (RFC 7515 §5.1/§7.2; RFC 7797):
            //    b64=true  : ASCII( Base64URL(protected) + "." + Base64URL(payload) )
            //    b64=false : ASCII( Base64URL(protected) + "." )  ||  RAW(payload)
            byte[] signingInput;
            if (b64false) {
                if (payloadFile == null) {
                    throw new IllegalArgumentException("b64=false requires --payload with RAW payload bytes.");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                byte[] raw  = loadDetachedPayloadPossiblyCanonicalized(); // optional RFC 8785 JCS
                signingInput = concat(left, raw);
            } else {
                if (detached) {
                    // For detached b64=true, reconstruct Base64URL(payload) from provided bytes.
                    if (payloadFile == null) {
                        throw new IllegalArgumentException("detached requires --payload (for b64=true).");
                    }
                    byte[] raw = loadDetachedPayloadPossiblyCanonicalized(); // optional RFC 8785 JCS
                    payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
                } else {
                    if (payloadB64 == null) {
                        throw new IllegalArgumentException("Embedded signature expects a 'payload' in the JWS.");
                    }
                }
                signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            }

            // 4) Decode signature bytes and obtain a PublicKey (PEM/XML/HEX or from certificate).
            byte[] sig = Base64.getUrlDecoder().decode(signatureB64);

            if (pubDir == null || pubFile == null) {
                throw new IllegalArgumentException("crypto mode requires --pub-dir and --pub-file (public key or certificate).");
            }

            PublicKey pub;
            try {
                // Try direct public key formats first (PEM/XML/HEX)
                pub = PublicKeyFactory.load(pubDir, pubFile);
            } catch (Exception e) {
                // Fallback: read certificate and extract public key
                var cl = new PEMCertificateLoader(pubDir, pubFile);
                cl.load();
                if (cl.getCertificate() == null) {
                    throw new IllegalArgumentException("Could not load a public key (neither key nor certificate).", e);
                }
                pub = cl.getCertificate().getPublicKey();
            }

            // 5) Cryptographic verification (RFC 7515 §5.2; algorithms per RFC 7518).
            //    For ECDSA, convert raw R||S (JWS form) -> DER (JCA expects DER).
            boolean ok = verifyJws(signingInput, sig, pub, resolvedAlg);
            System.out.println("VALID (crypto-only): " + ok);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== DSS / eIDAS verification ====================== */

    /**
     * Uses DSS to verify (JSON serialization expected). If a Compact JWS is given,
     * we wrap it into a minimal JSON object. Detached payload (if provided) is passed
     * to DSS as detached content. Configure DSS's CertificateVerifier to enable trust,
     * revocation (OCSP/CRL), TSL, etc. (ETSI TS 119 102/182).
     */
    private void verifyWithDss(String content) throws Exception {
        String jsonForDss = content;

        // DSS expects JOSE JSON; convert Compact to minimal JSON (single signature)
        if (!isJsonSerialization(content)) {
            String[] parts = content.split("\\.", -1);
            if (parts.length != 3) throw new IllegalArgumentException("Invalid compact JWS for DSS.");
            String protectedB64 = parts[0];
            String payloadB64   = parts[1];  // may be empty (detached)
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
        // Configure trust sources/revocation as needed for production
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        // Pass detached content (DSS will bind it correctly)
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
     * - RS512: "SHA512withRSA" (RFC 7518 – RSASSA-PKCS1-v1_5 with SHA-512)
     * - PS512: "RSASSA-PSS" with MGF1(SHA-512), saltLen=64 (RFC 7518 §3.5 – PS512 params)
     * - ES*  : "SHAxxxwithECDSA"; JWS provides raw R||S, while JCA expects DER, so we transcode.
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
                String jca = switch (alg) {
                    case "ES256" -> "SHA256withECDSA";
                    case "ES384" -> "SHA384withECDSA";
                    default -> "SHA512withECDSA";
                };
                Signature v = Signature.getInstance(jca);
                v.initVerify(pub);
                v.update(signingInput);
                // JWS provides fixed-length raw R||S; convert to DER for JCA verify.
                byte[] der = EcdsaDer.transcodeConcatToDer(sig, ecdsaFieldSizeBytes(alg));
                return v.verify(der);
            }
            default:
                throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
    }

    /** ECDSA field sizes in bytes for raw R||S (RFC 7518): P-256=32, P-384=48, P-521≈66. */
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
     * Heuristic: JSON serialization (including BG wrapper) must contain both
     * "protected" and "signature" fields. Compact lacks quotes and is dot-separated.
     */
    private static boolean isJsonSerialization(String s) {
        return s.contains("\"protected\"") && s.contains("\"signature\"");
    }

    /**
     * Minimal string extractor for JSON fields of the form:  "key":"value".
     * Sufficient for our simple single-signature envelope parsing here.
     */
    private static String extractJsonValue(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) throw new IllegalArgumentException("Missing JSON field " + keyWithQuotes);
        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon + 1);
        int q2 = json.indexOf('"', q1 + 1);
        if (colon < 0 || q1 < 0 || q2 < 0) throw new IllegalArgumentException("Malformed JSON near " + keyWithQuotes);
        return json.substring(q1 + 1, q2);
    }

    /** Concatenate two byte arrays. */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * Loads the external payload and optionally canonicalizes it via RFC 8785 (JCS),
     * if `--canonicalize-payload=jcs` is set. Only valid JSON (object/array) can be canonicalized.
     * Must mirror the signer’s canonicalization, otherwise verification will fail.
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

    /** Lightweight JSON check (object or array). */
    private static boolean looksLikeJson(String s) {
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) i++;
        if (i >= n) return false;
        char c = s.charAt(i);
        return c == '{' || c == '[';
    }
}
