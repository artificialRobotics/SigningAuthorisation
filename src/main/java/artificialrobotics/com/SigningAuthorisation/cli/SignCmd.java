package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PrivateKeyFactory;
import artificialrobotics.com.SigningAuthorisation.signingKeys.KeystorePrivateKeyLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.CertificateLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.jose.ProtectedHeader;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;
import artificialrobotics.com.SigningAuthorisation.jose.EcdsaDer;

import picocli.CommandLine;

import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * # SignCmd
 *
 * CLI command that produces JWS/JAdES-compatible signatures in:
 *  - JWS Compact Serialization (RFC 7515 §3.1),
 *  - JWS JSON Serialization (RFC 7515 §7.2; single signature object),
 *  - a domain-specific **Berlin Group (BG)** wrapper JSON.
 *
 * Supported features:
 *  - **Detached signatures** (RFC 7515 §7.2.1/§7.2.2; Compact uses `..` for empty payload section),
 *  - **Unencoded payload** (`"b64": false`) per RFC 7797, including mandatory `"crit":["b64"]`,
 *  - Algorithms per RFC 7518: **RS512**, **PS512** (RSA-PSS), **ES256/ES384/ES512** (ECDSA),
 *  - Optional **JSON Canonicalization (JCS)** of the payload (RFC 8785) and advertising it via
 *    `"etsiCanonicalization"` in the protected header (commonly used in JAdES profiles; ETSI TS 119 182),
 *  - Private key sources: **files** (PKCS#8 / PKCS#1 / XML / HEX) or **keystores** (PKCS12 / JKS).
 *
 * Emitted artifacts (for audit and reproducibility):
 *  - **JSON4Signature<out>**: the (optionally canonicalized) payload as UTF-8 text,
 *  - **HASH4Signature<out>**: Base64 (with padding) of the hash over the **actual JWS signing input**,
 *    i.e., over `Base64URL(protected) + "." + Base64URL(payload)` (or `+ RAW(payload)` when b64=false).
 *
 * Specifications:
 *  - RFC 7515 – JSON Web Signature (JWS)
 *  - RFC 7518 – JSON Web Algorithms (JWA)
 *  - RFC 7797 – JWS Unencoded Payload Option (b64=false)
 *  - RFC 8785 – JSON Canonicalization Scheme (JCS)
 *  - ETSI TS 119 182 – JAdES (context for additional header signaling and audit artifacts)
 */
@CommandLine.Command(
        name = "sign",
        description = "Sign payload to JWS (Compact, JSON or BG). Supports detached, RFC 7797 (b64=false), keystore and optional JSON canonicalization (JCS). Emits JSON4Signature* (payload text) and HASH4Signature* (Base64 digest of signing-input)."
)
public class SignCmd implements Runnable {

    // ---- Algorithms as defined by RFC 7518 (JWA) ----
    @CommandLine.Option(
            names="--alg",
            required=true,
            description="RS512 | PS512 | ES256 | ES384 | ES512")
    String alg;

    // ---- Payload whose BYTES are signed (RFC 7515 §5) ----
    @CommandLine.Option(
            names="--payload",
            required=true,
            description="Payload file; bytes are signed")
    Path payloadFile;

    // ---- Output format: JWS Compact / JWS JSON / Berlin Group wrapper ----
    @CommandLine.Option(
            names="--out-format",
            required=true,
            description="compact | json | bg (Berlin Group format)")
    String outFormat;

    // ---- Private key from file (various loaders in this project) ----
    @CommandLine.Option(names="--key-dir") Path keyDir;
    @CommandLine.Option(names="--key-file") String keyFile;

    // ---- Private key from keystore (PKCS12/JKS) ----
    @CommandLine.Option(names="--keystore", description="Path to keystore file (.p12/.pfx/.jks)")
    Path keystorePath;
    @CommandLine.Option(names="--keystoreType", description="Keystore type: PKCS12 | JKS (default: PKCS12)")
    String keystoreType = "PKCS12";
    @CommandLine.Option(names="--keystorePassword", description="Keystore password")
    String keystorePassword;
    @CommandLine.Option(names="--keyAlias", description="Alias of the private key entry in keystore")
    String keyAlias;
    @CommandLine.Option(names="--keyPassword", description="Private key password (if different from keystore password)")
    String keyPassword;

    // ---- Certificate material for x5u/x5c header params (RFC 7515 §4.1.5/§4.1.6) ----
    @CommandLine.Option(names="--cert-dir") Path certDir;
    @CommandLine.Option(names="--cert-file") String certFile;
    @CommandLine.Option(names="--x5u") String x5u;

    // ---- Detached & RFC 7797 (b64=false) controls ----
    @CommandLine.Option(names="--detached", description="Do not embed payload in the JWS (detached payload).")
    boolean detached;
    @CommandLine.Option(names="--b64false", description="Use RFC 7797 (unencoded payload); adds b64=false and crit:['b64'] to protected header.")
    boolean b64false;

    // ---- Protected Header controls (plus JAdES claims) ----
    @CommandLine.Option(names="--protectedHeaderFile", description="JSON file with protected header overrides (merged).")
    Path protectedHeaderFile;
    @CommandLine.Option(names="--sub", description="Sets/overrides 'sub' claim in protected header.")
    String subClaim;
    @CommandLine.Option(names="--sigT", description="Sets/overrides 'sigT' claim (use 'CURRENT' for now-UTC).")
    String sigTClaim;

    // ---- JSON canonicalization of payload (RFC 8785 JCS) ----
    @CommandLine.Option(names="--canonicalize-payload", description="Canonicalize JSON payload before signing. Supported value: jcs")
    String canonicalizePayload; // expected "jcs"

    @CommandLine.Option(
            names="--out",
            required=true,
            description="Output file for resulting JWS (compact, JSON, or BG)")
    Path outFile;

    @Override
    public void run() {
        try {
            // Initialize crypto provider(s) (e.g., BouncyCastle) as configured by the project.
            new InitBC();

            // (0) Validate key source: either keystore OR file must be provided
            final boolean useKeystore = (keystorePath != null);
            if (useKeystore) {
                if (keystorePassword == null)
                    throw new IllegalArgumentException("--keystorePassword is required when --keystore is used.");
                if (keyAlias == null || keyAlias.isBlank())
                    throw new IllegalArgumentException("--keyAlias is required when --keystore is used.");
            } else {
                if (keyDir == null || keyFile == null)
                    throw new IllegalArgumentException("Either provide --keystore ... OR --key-dir and --key-file.");
            }

            // (1) Build the Protected Header (RFC 7515 §4).
            //     - Mandatory: "alg" (RFC 7518; JWA)
            //     - Optional: x5u/x5c (RFC 7515 §4.1.5/§4.1.6)
            //     - If RFC 7797 is used: "b64": false and "crit" must include "b64".
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("alg", alg);
            if (x5u != null && !x5u.isBlank()) base.put("x5u", x5u);
            if (b64false) base.put("b64", false);

            // x5c chain (Base64 DER) per RFC 7515 §4.1.6
            if (certDir != null && certFile != null) {
                CertificateLoader cl = new PEMCertificateLoader(certDir, certFile);
                cl.load();
                var chain = cl.getCertificateChain();
                if (chain != null && !chain.isEmpty()) {
                    List<String> x5c = new ArrayList<>();
                    for (var c : chain) x5c.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                    base.put("x5c", x5c);
                }
            }

            // ProtectedHeader manages deep copies and auto-crit for sigT/sub/b64.
            ProtectedHeader ph = new ProtectedHeader(base);

            // Merge optional header overrides from JSON (e.g. JAdES/domain-specific claims).
            if (protectedHeaderFile != null) {
                String overridesJson = Files.readString(protectedHeaderFile, StandardCharsets.UTF_8);
                ph.applyOverridesJson(overridesJson);
            }
            // CLI-level claims (commonly used in JAdES contexts)
            if (subClaim != null) ph.put("sub", subClaim);
            if (sigTClaim != null) ph.put("sigT", sigTClaim);

            // RFC 7797 enforcement: if "b64": false, "b64" MUST be listed in "crit".
            if (b64false) ensureCritContains(ph, "b64");

            // RFC 8785 (JCS): signal that canonicalization was applied, and mark as critical.
            // ETSI TS 119 182 contexts often use such header signaling.
            boolean signalCanonicalization = (canonicalizePayload != null && canonicalizePayload.equalsIgnoreCase("jcs"));
            if (signalCanonicalization) {
                ph.put("etsiCanonicalization", "http://json-canonicalization.org/algorithm");
                ensureCritContains(ph, "etsiCanonicalization");
            }

            // Serialize protected header (RFC 7515 §5.1 Step 1) and Base64URL-encode it.
            String protectedJsonCompact = ph.toCompactJson();
            String protectedJsonPretty  = ph.toPrettyJson();
            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(protectedJsonCompact.getBytes(StandardCharsets.UTF_8));

            // Print header for audit/debug
            System.out.println("=== Protected Header (final, pretty) ===");
            System.out.println(protectedJsonPretty);
            System.out.println("=== Protected Header (final, Base64URL) ===");
            System.out.println(protectedB64);
            System.out.println("=========================================");

            // (2) Load payload and optionally canonicalize it using RFC 8785 (JCS).
            //     Canonicalization affects the EXACT bytes that will be signed.
            byte[] payloadOriginal = Files.readAllBytes(payloadFile);
            byte[] payloadEffective = payloadOriginal;

            if (signalCanonicalization) {
                String raw = new String(payloadOriginal, StandardCharsets.UTF_8);
                if (!looksLikeJson(raw)) {
                    // JCS requires a valid JSON object or array.
                    throw new IllegalArgumentException("--canonicalize-payload=jcs requires valid JSON payload.");
                }
                String canonical = JsonCanonicalizerJcs.canonicalize(raw);
                payloadEffective = canonical.getBytes(StandardCharsets.UTF_8);
            }

            // (3) Build the JWS signing input (RFC 7515 §5.1/§7.2; RFC 7797):
            //     b64=true  : ASCII( Base64URL(protected) + "." + Base64URL(payload) )
            //     b64=false : ASCII( Base64URL(protected) + "." )  ||  RAW(payload)
            byte[] signingInputBytes;
            String payloadB64 = null;
            boolean headerB64False = Boolean.FALSE.equals(ph.asObjectMap().get("b64"));

            if (headerB64False) {
                // RFC 7797: Compact cannot embed RAW payload → must be detached for Compact.
                if ("compact".equalsIgnoreCase(outFormat) && !detached) {
                    throw new IllegalArgumentException("Compact + b64=false requires --detached (Compact cannot embed raw payload).");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                signingInputBytes = concat(left, payloadEffective);
            } else {
                payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadEffective);
                signingInputBytes = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            }

            // (3b) Emit artifacts:
            //   - JSON4Signature*: the effective payload as UTF-8 text (after optional JCS)
            //   - HASH4Signature*: Base64( hash(signingInputBytes) )
            writePayloadTextAndHashArtifacts(payloadEffective, signingInputBytes, outFile, alg);

            // (4) Load private key (file-based loaders or keystore)
            PrivateKey priv;
            if (useKeystore) {
                Path ksDir  = keystorePath.getParent();
                String ksFile = keystorePath.getFileName().toString();

                KeystorePrivateKeyLoader ksLoader = new KeystorePrivateKeyLoader(
                        ksDir,
                        ksFile,
                        keystoreType,
                        (keystorePassword != null ? keystorePassword.toCharArray() : null),
                        keyAlias,
                        (keyPassword != null && !keyPassword.isBlank() ? keyPassword.toCharArray() : null)
                );
                ksLoader.load();
                priv = ksLoader.getPrivateKey();
            } else {
                priv = PrivateKeyFactory.load(keyDir, keyFile);
            }

            // (5) Compute signature (RFC 7515 §5.2; algorithms per RFC 7518).
            //     For ECDSA, convert DER → raw R||S to be JWS-compliant (RFC 7515 §3, §6; RFC 7518 §3.4).
            byte[] sig = signJws(signingInputBytes, priv, alg);
            String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

            // (6) Render output in the selected format
            String result;
            if ("compact".equalsIgnoreCase(outFormat)) {
                // Detached compact form uses `..` when payload is omitted.
                result = detached
                        ? protectedB64 + ".." + sigB64
                        : protectedB64 + "." + payloadB64 + "." + sigB64;
            }
            else if ("json".equalsIgnoreCase(outFormat)) {
                // Minimal JSON Serialization with a single signature object.
                result = detached
                        ? String.format("{\"protected\":\"%s\",\"signature\":\"%s\"}", protectedB64, sigB64)
                        : String.format("{\"payload\":\"%s\",\"protected\":\"%s\",\"signature\":\"%s\"}",
                                payloadB64, protectedB64, sigB64);
            }
            else if ("bg".equalsIgnoreCase(outFormat)) {
                // Berlin Group wrapper; typically used with detached payloads.
                result = """
                        {
                          "signatureData": {
                            "protected": "%s",
                            "signature": "%s"
                          }
                        }
                        """.formatted(protectedB64, sigB64).trim();
            }
            else {
                throw new IllegalArgumentException("Unsupported --out-format: " + outFormat);
            }

            Files.writeString(outFile, result, StandardCharsets.UTF_8);
            System.out.println("Wrote: " + outFile.toAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== Helper methods ====================== */

    /**
     * Ensure that the given header name is listed in {@code crit}.
     * RFC 7515 §4.1.11 mandates that recipients MUST understand all parameters listed in "crit".
     * RFC 7797 requires "b64" to be present in "crit" when "b64": false is used.
     */
    private static void ensureCritContains(ProtectedHeader ph, String name) {
        List<String> critList;
        Object critObj = ph.asObjectMap().get("crit");
        if (critObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> l = (List<String>) critObj;
            critList = new ArrayList<>(l);
        } else {
            critList = new ArrayList<>();
        }
        if (!critList.contains(name)) {
            critList.add(name);
            ph.put("crit", critList); // write back to header
        }
    }

    /**
     * Writes:
     *  - JSON4Signature<out>: payload as UTF-8 text (after optional JCS), for audit/debug only.
     *  - HASH4Signature<out>: Base64( digest(signingInputBytes) ), where the digest function
     *    is chosen from the JWS alg family (256/384/512).
     *
     * Notes:
     *  - The digest covers the **JWS signing input** per RFC 7515 §5.1/§5.2 (not just the payload).
     *  - In JAdES workflows (ETSI TS 119 182) it is common to store such artifacts for evidence.
     */
    private static void writePayloadTextAndHashArtifacts(byte[] payloadEffective,
                                                         byte[] signingInputBytes,
                                                         Path outFile,
                                                         String alg) throws Exception {
        Path baseDir = outFile.toAbsolutePath().getParent();
        if (baseDir == null) baseDir = Path.of(".");
        String outName = outFile.getFileName().toString();

        Path json4SigPath = baseDir.resolve("JSON4Signature" + outName);
        Path hash4SigPath = baseDir.resolve("HASH4Signature" + outName);

        // Render payload text as UTF-8 (malformed sequences are replaced for readability)
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        String payloadText = dec.decode(java.nio.ByteBuffer.wrap(payloadEffective)).toString();
        Files.writeString(json4SigPath, payloadText, StandardCharsets.UTF_8);

        // Derive digest algorithm from JWS alg (RFC 7518)
        String digestAlg = switch (alg) {
            case "ES256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            case "ES512", "RS512", "PS512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };
        MessageDigest md = MessageDigest.getInstance(digestAlg);
        byte[] digest = md.digest(signingInputBytes);
        String digestB64 = Base64.getEncoder().encodeToString(digest); // Base64 (with padding)
        Files.writeString(hash4SigPath, digestB64 + System.lineSeparator(), StandardCharsets.UTF_8);
    }

    /**
     * Signs the JWS signing input using the selected algorithm.
     *
     * - RS512: "SHA512withRSA" (RFC 7518 – RSASSA-PKCS1-v1_5 with SHA-512)
     * - PS512: "RSASSA-PSS" with MGF1(SHA-512) and saltLen=64 (RFC 7518 §3.5; JWS "PS512")
     * - ES*  : "SHAxxxwithECDSA" then convert DER → raw R||S per JWS (RFC 7515 §3/§6; RFC 7518 §3.4)
     */
    private static byte[] signJws(byte[] signingInput, PrivateKey key, String alg) throws Exception {
        switch (alg) {
            case "RS512" -> {
                Signature s = Signature.getInstance("SHA512withRSA");
                s.initSign(key);
                s.update(signingInput);
                return s.sign();
            }
            case "PS512" -> {
                Signature s = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"), 64, 1);
                s.setParameter(pss);
                s.initSign(key);
                s.update(signingInput);
                return s.sign();
            }
            case "ES256", "ES384", "ES512" -> {
                String jca = switch (alg) {
                    case "ES256" -> "SHA256withECDSA";
                    case "ES384" -> "SHA384withECDSA";
                    default -> "SHA512withECDSA";
                };
                Signature s = Signature.getInstance(jca);
                s.initSign(key);
                s.update(signingInput);
                byte[] derSig = s.sign();
                // JWS requires fixed-length raw R||S; transcode from DER form.
                return EcdsaDer.transcodeDerToConcat(derSig, ecdsaFieldSizeBytes(alg));
            }
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
    }

    /** ECDSA field sizes for raw R||S in JWS (RFC 7518): P-256=32, P-384=48, P-521≈66. */
    private static int ecdsaFieldSizeBytes(String alg) {
        return switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512" -> 66;
            default -> throw new IllegalArgumentException("Unknown ECDSA alg: " + alg);
        };
    }

    /** Lightweight JSON check (object/array) – required before JCS canonicalization. */
    private static boolean looksLikeJson(String s) {
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) i++;
        if (i >= n) return false;
        char c = s.charAt(i);
        return c == '{' || c == '[';
    }

    /** Byte concatenation helper. */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}



