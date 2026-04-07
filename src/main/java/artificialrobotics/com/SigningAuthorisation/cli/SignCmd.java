package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PrivateKeyFactory;
import artificialrobotics.com.SigningAuthorisation.signingKeys.KeystorePrivateKeyLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.CertificateLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.jose.ProtectedHeader;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

import picocli.CommandLine;

import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * # SignCmd
 *
 * CLI command that produces JWS/JAdES-compatible signatures in:
 *  - JWS Compact Serialization (RFC 7515 §3.1),
 *  - JWS JSON Serialization (RFC 7515 §7.2; single signature object),
 *  - a domain-specific Berlin Group (BG) wrapper JSON.
 *
 * Supported features:
 *  - Detached signatures (RFC 7515 §7.2.1/§7.2.2),
 *  - Unencoded payload ("b64": false) per RFC 7797,
 *  - Algorithms: RS256, RS512, PS256, PS512, ES256/ES384/ES512 (RFC 7518),
 *  - Optional payload canonicalization via JCS (RFC 8785) signaled by "canonAlg",
 *  - Optional x5t#S256 header generation,
 *  - Optional final allow-list filtering for "crit" via --critClaimList,
 *  - Optional iat generation,
 *  - Keys from file or keystore.
 *
 * IMPORTANT (project protocol alignment):
 *  - For ES256/ES384/ES512 in this project configuration, a PRE-HASH model is used:
 *      digest = HASH(signingInputBytes)
 *      derSignature = NONEwithECDSA over digest
 *      jwsSignature = JOSE raw R||S converted from DER
 *
 *    This preserves the project’s external pre-hash model while emitting a
 *    JWS-compliant ECDSA signature encoding.
 *
 *  - RS256/RS512 use standard RSA PKCS#1 v1.5 signing over signingInputBytes.
 *  - PS256/PS512 use standard RSASSA-PSS signing over signingInputBytes.
 */
@CommandLine.Command(
        name = "sign",
        description = "Sign payload to JWS (Compact, JSON or BG). Supports detached, RFC 7797 (b64=false), keystore and optional JSON canonicalization (JCS). Emits JSON4Signature* (payload text) and HASH4Signature* (Base64 digest of signing-input)."
)
public class SignCmd implements Runnable {

    @CommandLine.Option(
            names = "--alg",
            required = true,
            description = "RS256 | RS512 | PS256 | PS512 | ES256 | ES384 | ES512")
    String alg;

    @CommandLine.Option(
            names = "--payload",
            required = true,
            description = "Payload file; bytes are signed")
    Path payloadFile;

    @CommandLine.Option(
            names = "--out-format",
            required = true,
            description = "compact | json | bg (Berlin Group format)")
    String outFormat;

    @CommandLine.Option(names = "--key-dir")
    Path keyDir;

    @CommandLine.Option(names = "--key-file")
    String keyFile;

    @CommandLine.Option(names = "--keystore", description = "Path to keystore file (.p12/.pfx/.jks)")
    Path keystorePath;

    @CommandLine.Option(names = "--keystoreType", description = "Keystore type: PKCS12 | JKS (default: PKCS12)")
    String keystoreType = "PKCS12";

    @CommandLine.Option(names = "--keystorePassword", description = "Keystore password")
    String keystorePassword;

    @CommandLine.Option(names = "--keyAlias", description = "Alias of the private key entry in keystore")
    String keyAlias;

    @CommandLine.Option(names = "--keyPassword", description = "Private key password (if different from keystore password)")
    String keyPassword;

    @CommandLine.Option(names = "--cert-dir")
    Path certDir;

    @CommandLine.Option(names = "--cert-file")
    String certFile;

    @CommandLine.Option(names = "--x5u")
    String x5u;

    @CommandLine.Option(names = "--detached", description = "Do not embed payload in the JWS (detached payload).")
    boolean detached;

    @CommandLine.Option(names = "--b64false", description = "Use RFC 7797 (unencoded payload); adds b64=false and crit:['b64'] to protected header.")
    boolean b64false;

    @CommandLine.Option(names = "--protectedHeaderFile", description = "JSON file with protected header overrides (merged).")
    Path protectedHeaderFile;

    @CommandLine.Option(names = "--sub", description = "Sets/overrides 'sub' claim in protected header.")
    String subClaim;

    @CommandLine.Option(names = "--sigT", description = "Sets/overrides 'sigT' claim (use 'CURRENT' for now-UTC).")
    String sigTClaim;

    @CommandLine.Option(names = "--iat", description = "Generate protected header 'iat' as NumericDate. If sigT exists, iat is derived from sigT; otherwise current time is used.")
    boolean iatFlag;

    @CommandLine.Option(names = "--canonicalize-payload", description = "Canonicalize JSON payload before signing. Supported value: jcs")
    String canonicalizePayload;

    @CommandLine.Option(
            names = "--x5t#S256",
            description = "Generate protected header 'x5t#S256' from the signing certificate (Base64URL SHA-256 over certificate DER)."
    )
    boolean x5tS256Flag;

    /**
     * Optional allow-list filter for "crit".
     * Example: --critClaimList b64,sigT,sigD
     *
     * If set, "crit" is filtered to these values (and only if the corresponding claim is present).
     */
    @CommandLine.Option(
            names = "--critClaimList",
            split = ",",
            description = "Comma-separated allow-list for 'crit'. If provided, only these claims may appear under 'crit' (and only if present). Example: --critClaimList b64,sigT,sigD"
    )
    List<String> critClaimList;

    @CommandLine.Option(
            names = "--out",
            required = true,
            description = "Output file for resulting JWS (compact, JSON, or BG)")
    Path outFile;

    @Override
    public void run() {
        try {
            new InitBC();

            // (0) Validate key source
            final boolean useKeystore = (keystorePath != null);
            if (useKeystore) {
                if (keystorePassword == null) {
                    throw new IllegalArgumentException("--keystorePassword is required when --keystore is used.");
                }
                if (keyAlias == null || keyAlias.isBlank()) {
                    throw new IllegalArgumentException("--keyAlias is required when --keystore is used.");
                }
            } else {
                if (keyDir == null || keyFile == null) {
                    throw new IllegalArgumentException("Either provide --keystore ... OR --key-dir and --key-file.");
                }
            }

            // (1) Build Protected Header base
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("alg", alg);
            if (x5u != null && !x5u.isBlank()) {
                base.put("x5u", x5u);
            }
            if (b64false) {
                base.put("b64", false);
            }

            // Add x5c chain (optional)
            if (certDir != null && certFile != null) {
                CertificateLoader cl = new PEMCertificateLoader(certDir, certFile);
                cl.load();
                var chain = cl.getCertificateChain();
                if (chain != null && !chain.isEmpty()) {
                    List<String> x5c = new ArrayList<>();
                    for (var c : chain) {
                        x5c.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                    }
                    base.put("x5c", x5c);
                }
            }

            // Optional x5t#S256
            if (x5tS256Flag) {
                byte[] certDer = loadSigningCertificateDer(useKeystore);
                String thumbprint = base64UrlSha256(certDer);
                base.put("x5t#S256", thumbprint);
            }

            ProtectedHeader ph = new ProtectedHeader(base);

            // Apply optional header overrides
            if (protectedHeaderFile != null) {
                String overridesJson = Files.readString(protectedHeaderFile, StandardCharsets.UTF_8);
                ph.applyOverridesJson(overridesJson);
            }
            if (subClaim != null) {
                ph.put("sub", subClaim);
            }
            if (sigTClaim != null) {
                ph.put("sigT", sigTClaim);
            }

            // Optional iat generation
            if (iatFlag) {
                long iatValue = deriveIatFromEffectiveSigTOrNow(ph);
                ph.put("iat", iatValue);
            }

            // RFC 7797: ensure b64 in crit if b64=false
            if (b64false) {
                ensureCritContains(ph, "b64");
            }

            // Optional payload canonicalization signaling (JCS / RFC 8785)
            boolean signalCanonicalization = (canonicalizePayload != null && canonicalizePayload.equalsIgnoreCase("jcs"));
            if (signalCanonicalization) {
                ph.put("canonAlg", "http://json-canonicalization.org/algorithm");
                ensureCritContains(ph, "canonAlg");
            }

            // Optional final "crit" allow-list filter
            if (critClaimList != null && !critClaimList.isEmpty()) {
                ph.applyCritAllowList(critClaimList);
            }

            // Serialize protected header
            String protectedJsonCompact = ph.toCompactJson();
            String protectedJsonPretty = ph.toPrettyJson();
            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(protectedJsonCompact.getBytes(StandardCharsets.UTF_8));

            // Print final protected header
            System.out.println("=== Protected Header (final, pretty) ===");
            System.out.println(protectedJsonPretty);
            System.out.println("=== Protected Header (final, Base64URL) ===");
            System.out.println(protectedB64);
            System.out.println("=========================================");

            // (2) Load payload + optional JCS canonicalization
            byte[] payloadOriginal = Files.readAllBytes(payloadFile);
            byte[] payloadEffective = payloadOriginal;

            if (signalCanonicalization) {
                String raw = new String(payloadOriginal, StandardCharsets.UTF_8);
                if (!looksLikeJson(raw)) {
                    throw new IllegalArgumentException("--canonicalize-payload=jcs requires valid JSON payload.");
                }
                String canonical = JsonCanonicalizerJcs.canonicalize(raw);
                payloadEffective = canonical.getBytes(StandardCharsets.UTF_8);
            }

            // (3) Build JWS Signing Input
            byte[] signingInputBytes;
            String payloadB64 = null;
            byte[] payloadBytesForSigning;
            boolean headerB64False = Boolean.FALSE.equals(ph.asObjectMap().get("b64"));

            if (headerB64False) {
                if ("compact".equalsIgnoreCase(outFormat) && !detached) {
                    throw new IllegalArgumentException("Compact + b64=false requires --detached (Compact cannot embed raw payload).");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                signingInputBytes = concat(left, payloadEffective);
                payloadBytesForSigning = payloadEffective;
            } else {
                payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadEffective);
                signingInputBytes = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
                payloadBytesForSigning = payloadB64.getBytes(StandardCharsets.US_ASCII);
            }

            // (3b) Emit artifacts
            writePayloadTextAndHashArtifacts(payloadEffective, payloadBytesForSigning, signingInputBytes, outFile, alg);

            // (4) Load private key
            PrivateKey priv;
            if (useKeystore) {
                Path ksDir = keystorePath.toAbsolutePath().getParent();
                if (ksDir == null) {
                    ksDir = Path.of(".").toAbsolutePath();
                }
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

            // (5) Compute signature
            byte[] signingInputDigest = computeSigningInputDigest(signingInputBytes, alg);
            byte[] sig = signJws(signingInputBytes, signingInputDigest, priv, alg);
            String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

            // (6) Render output
            String result;
            if ("compact".equalsIgnoreCase(outFormat)) {
                result = detached
                        ? protectedB64 + ".." + sigB64
                        : protectedB64 + "." + payloadB64 + "." + sigB64;
            } else if ("json".equalsIgnoreCase(outFormat)) {
                result = detached
                        ? String.format("{\"protected\":\"%s\",\"signature\":\"%s\"}", protectedB64, sigB64)
                        : String.format("{\"payload\":\"%s\",\"protected\":\"%s\",\"signature\":\"%s\"}",
                        payloadB64, protectedB64, sigB64);
            } else if ("bg".equalsIgnoreCase(outFormat)) {
                result = """
                        {
                          "signatureData": {
                            "protected": "%s",
                            "signature": "%s"
                          }
                        }
                        """.formatted(protectedB64, sigB64).trim();
            } else {
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
            ph.put("crit", critList);
        }
    }

    private long deriveIatFromEffectiveSigTOrNow(ProtectedHeader ph) {
        Object sigT = ph.asObjectMap().get("sigT");
        if (sigT == null) {
            return Instant.now().getEpochSecond();
        }
        if (sigT instanceof Number n) {
            return n.longValue();
        }
        if (sigT instanceof String s) {
            try {
                return Instant.parse(s).getEpochSecond();
            } catch (Exception e) {
                throw new IllegalArgumentException("Could not derive iat from sigT. Expected ISO-8601 instant string, but got: " + s, e);
            }
        }
        throw new IllegalArgumentException("Could not derive iat from sigT. Unsupported sigT type: " + sigT.getClass().getName());
    }

    /**
     * Loads the DER-encoded signing certificate from:
     * - certDir/certFile, if provided
     * - otherwise from the keystore alias, if keystore mode is used
     */
    private byte[] loadSigningCertificateDer(boolean useKeystore) throws Exception {
        if (certDir != null && certFile != null) {
            CertificateLoader cl = new PEMCertificateLoader(certDir, certFile);
            cl.load();
            if (cl.getCertificate() == null) {
                throw new IllegalArgumentException("Could not load signing certificate from --cert-dir/--cert-file.");
            }
            return cl.getCertificate().getEncoded();
        }

        if (useKeystore) {
            KeyStore ks = KeyStore.getInstance(keystoreType);
            try (var is = Files.newInputStream(keystorePath)) {
                ks.load(is, keystorePassword.toCharArray());
            }
            Certificate cert = ks.getCertificate(keyAlias);
            if (cert == null) {
                throw new IllegalArgumentException("Could not load signing certificate from keystore alias: " + keyAlias);
            }
            return cert.getEncoded();
        }

        throw new IllegalArgumentException("--x5t#S256 requires a certificate source. Provide --cert-dir/--cert-file or use --keystore with a certificate-bearing alias.");
    }

    private static String base64UrlSha256(byte[] input) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static void writePayloadTextAndHashArtifacts(byte[] payloadEffective,
                                                         byte[] payloadBytesForSigning,
                                                         byte[] signingInputBytes,
                                                         Path outFile,
                                                         String alg) throws Exception {
        Path baseDir = outFile.toAbsolutePath().getParent();
        if (baseDir == null) {
            baseDir = Path.of(".");
        }
        String outName = outFile.getFileName().toString();

        Path json4SigPath = baseDir.resolve("JSON4Signature" + outName + ".json");
        Path hash4SigPath = baseDir.resolve("HASH4Signature" + outName + ".txt");
        Path hashPayload4SigPath = baseDir.resolve("HASHPayload" + outName + ".txt");
        Path b64Payload4SigPath = baseDir.resolve("B64Payload" + outName + ".txt");

        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        String payloadText = dec.decode(java.nio.ByteBuffer.wrap(payloadEffective)).toString();
        Files.writeString(json4SigPath, payloadText, StandardCharsets.UTF_8);

        String digestAlg = switch (alg) {
            case "ES256", "RS256", "PS256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            case "ES512", "RS512", "PS512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };
        MessageDigest md = MessageDigest.getInstance(digestAlg);
        byte[] digest = md.digest(signingInputBytes);
        String digestB64 = Base64.getEncoder().encodeToString(digest);
        Files.writeString(hash4SigPath, digestB64 + System.lineSeparator(), StandardCharsets.UTF_8);

        Files.writeString(b64Payload4SigPath, Base64.getEncoder().encodeToString(payloadEffective), StandardCharsets.UTF_8);

        md = MessageDigest.getInstance(digestAlg);
        digest = md.digest(payloadBytesForSigning);
        digestB64 = Base64.getEncoder().encodeToString(digest);
        Files.writeString(hashPayload4SigPath, digestB64 + System.lineSeparator(), StandardCharsets.UTF_8);
    }

    private static byte[] computeSigningInputDigest(byte[] signingInputBytes, String alg) throws Exception {
        String digestAlg = switch (alg) {
            case "ES256", "RS256", "PS256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            case "ES512", "RS512", "PS512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };
        return MessageDigest.getInstance(digestAlg).digest(signingInputBytes);
    }

    /**
     * Signs the signing input (standard) OR, for the ES* pre-hash protocol, signs a precomputed digest.
     *
     * - RS256/RS512: standard JWS path (hashing inside algorithm)
     * - PS256/PS512: standard JWS path (RSASSA-PSS over signingInputBytes; hashing inside)
     * - ES256/ES384/ES512: project protocol path
     *     derSignature = NONEwithECDSA over digest
     *     jwsSignature = DER -> raw R||S
     */
    private static byte[] signJws(byte[] signingInputBytes,
                                  byte[] signingInputDigest,
                                  PrivateKey key,
                                  String alg) throws Exception {
        switch (alg) {
            case "RS256" -> {
                Signature s = Signature.getInstance("SHA256withRSA");
                s.initSign(key);
                s.update(signingInputBytes);
                return s.sign();
            }
            case "RS512" -> {
                Signature s = Signature.getInstance("SHA512withRSA");
                s.initSign(key);
                s.update(signingInputBytes);
                return s.sign();
            }
            case "PS256" -> {
                Signature s = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-256", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-256"), 32, 1);
                s.setParameter(pss);
                s.initSign(key);
                s.update(signingInputBytes);
                return s.sign();
            }
            case "PS512" -> {
                Signature s = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"), 64, 1);
                s.setParameter(pss);
                s.initSign(key);
                s.update(signingInputBytes);
                return s.sign();
            }
            case "ES256", "ES384", "ES512" -> {
                Signature s = Signature.getInstance("NONEwithECDSA", "BC");
                s.initSign(key);
                s.update(signingInputDigest);
                byte[] derSig = s.sign();
                return transcodeDerToConcat(derSig, ecdsaFieldSizeBytes(alg));
            }
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
    }

    private static int ecdsaFieldSizeBytes(String alg) {
        return switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512" -> 66; // P-521
            default -> throw new IllegalArgumentException("Unknown ECDSA alg: " + alg);
        };
    }

    /**
     * Converts ASN.1 DER encoded ECDSA signature into JOSE raw R||S format.
     */
    private static byte[] transcodeDerToConcat(byte[] derSignature, int outputLength) {
        if (derSignature == null || derSignature.length < 8 || derSignature[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature format.");
        }

        int offset;
        int seqLength;

        if ((derSignature[1] & 0x80) == 0) {
            seqLength = derSignature[1] & 0x7F;
            offset = 2;
        } else {
            int lenBytes = derSignature[1] & 0x7F;
            if (lenBytes < 1 || lenBytes > 2) {
                throw new IllegalArgumentException("Unsupported DER length encoding.");
            }
            seqLength = 0;
            for (int i = 0; i < lenBytes; i++) {
                seqLength = (seqLength << 8) | (derSignature[2 + i] & 0xFF);
            }
            offset = 2 + lenBytes;
        }

        if (offset + seqLength != derSignature.length) {
            throw new IllegalArgumentException("Invalid DER sequence length.");
        }

        if (derSignature[offset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER format: expected INTEGER for R.");
        }
        int rLen = derSignature[offset + 1] & 0xFF;
        int rOffset = offset + 2;

        int sTagOffset = rOffset + rLen;
        if (sTagOffset >= derSignature.length || derSignature[sTagOffset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER format: expected INTEGER for S.");
        }
        int sLen = derSignature[sTagOffset + 1] & 0xFF;
        int sOffset = sTagOffset + 2;

        byte[] concat = new byte[2 * outputLength];

        copyDerIntegerToFixed(derSignature, rOffset, rLen, concat, 0, outputLength);
        copyDerIntegerToFixed(derSignature, sOffset, sLen, concat, outputLength, outputLength);

        return concat;
    }

    private static void copyDerIntegerToFixed(byte[] der, int srcOffset, int srcLen,
                                              byte[] dest, int destOffset, int destLen) {
        while (srcLen > 1 && der[srcOffset] == 0x00) {
            srcOffset++;
            srcLen--;
        }

        if (srcLen > destLen) {
            throw new IllegalArgumentException("DER integer too large for expected JOSE field size.");
        }

        int pad = destLen - srcLen;
        for (int i = 0; i < pad; i++) {
            dest[destOffset + i] = 0x00;
        }
        System.arraycopy(der, srcOffset, dest, destOffset + pad, srcLen);
    }

    private static boolean looksLikeJson(String s) {
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        if (i >= n) {
            return false;
        }
        char c = s.charAt(i);
        return c == '{' || c == '[';
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}