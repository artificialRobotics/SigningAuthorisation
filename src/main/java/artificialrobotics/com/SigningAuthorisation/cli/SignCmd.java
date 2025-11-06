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

@CommandLine.Command(
        name = "sign",
        description = "Sign payload to JWS (Compact or JSON). Supports detached, RFC 7797 (b64=false), keystore and optional JSON canonicalization (JCS). Emits JSON4Signature* (payload text) and HASH4Signature* (Base64 digest of signing-input)."
)
public class SignCmd implements Runnable {

    @CommandLine.Option(names="--alg", required=true, description="RS512 | PS512 | ES256 | ES384 | ES512")
    String alg;

    @CommandLine.Option(names="--payload", required=true, description="Payload file; bytes are signed")
    Path payloadFile;

    @CommandLine.Option(names="--out-format", required=true, description="compact | json")
    String outFormat;

    // --- Private Key aus Datei ---
    @CommandLine.Option(names="--key-dir") Path keyDir;
    @CommandLine.Option(names="--key-file") String keyFile;

    // --- Keystore (PKCS12/JKS) ---
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

    // Zertifikate (x5c/x5u)
    @CommandLine.Option(names="--cert-dir") Path certDir;
    @CommandLine.Option(names="--cert-file") String certFile;
    @CommandLine.Option(names="--x5u") String x5u;

    // Detached / RFC 7797 (b64=false)
    @CommandLine.Option(names="--detached", description="Do not embed payload in the JWS (detached payload).")
    boolean detached;
    @CommandLine.Option(names="--b64false", description="Use RFC 7797 (unencoded payload); adds b64=false and crit:['b64'] to protected header.")
    boolean b64false;

    // Protected Header Steuerung
    @CommandLine.Option(names="--protectedHeaderFile", description="JSON file with protected header overrides (merged).")
    Path protectedHeaderFile;
    @CommandLine.Option(names="--sub", description="Sets/overrides 'sub' claim in protected header.")
    String subClaim;
    @CommandLine.Option(names="--sigT", description="Sets/overrides 'sigT' claim (use 'CURRENT' for now-UTC).")
    String sigTClaim;

    // Payload-Kanonisierung
    @CommandLine.Option(names="--canonicalize-payload", description="Canonicalize JSON payload before signing. Supported value: jcs")
    String canonicalizePayload; // expected "jcs"

    @CommandLine.Option(names="--out", required=true, description="Output file for resulting JWS (compact or JSON)")
    Path outFile;

    @Override
    public void run() {
        try {
            new InitBC(); // Provider initialisieren

            // --- 0) Eingabevalidierung Key-Quelle ---
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

            // --- 1) Protected Header aufbauen ---
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("alg", alg);
            if (b64false) base.put("b64", false);
            if (x5u != null && !x5u.isBlank()) base.put("x5u", x5u);

            // optional x5c-Kette
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

            ProtectedHeader ph = new ProtectedHeader(base);
            if (protectedHeaderFile != null) {
                String overridesJson = Files.readString(protectedHeaderFile, StandardCharsets.UTF_8);
                ph.applyOverridesJson(overridesJson);
            }
            if (subClaim != null) ph.put("sub", subClaim);
            if (sigTClaim != null) ph.put("sigT", sigTClaim);

            // etsiCanonicalization bei --canonicalize-payload=jcs setzen + crit ergänzen
            boolean signalCanonicalization = (canonicalizePayload != null && canonicalizePayload.equalsIgnoreCase("jcs"));
            if (signalCanonicalization) {
                ph.put("etsiCanonicalization", "http://json-canonicalization.org/algorithm");
                Map<String, Object> hdr = ph.asObjectMap();
                Object critObj = hdr.get("crit");
                List<String> critList;
                if (critObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<String> list = (List<String>) critObj;
                    critList = list;
                } else {
                    critList = new ArrayList<>();
                    hdr.put("crit", critList);
                }
                if (!critList.contains("etsiCanonicalization")) {
                    critList.add("etsiCanonicalization");
                }
            }

            String protectedJsonCompact = ph.toCompactJson();
            String protectedJsonPretty  = ph.toPrettyJson();
            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(protectedJsonCompact.getBytes(StandardCharsets.UTF_8));

            // Header-Preview
            System.out.println("=== Protected Header (final, pretty) ===");
            System.out.println(protectedJsonPretty);
            System.out.println("=== Protected Header (final, Base64URL) ===");
            System.out.println(protectedB64);
            System.out.println("=========================================");

            // --- 2) Payload laden & ggf. JCS-kanonisieren ---
            byte[] payloadOriginal = Files.readAllBytes(payloadFile);
            byte[] payloadEffective = payloadOriginal;

            boolean doCanonicalize = signalCanonicalization; // gleiche Bedingung wie Header-Claim
            if (doCanonicalize) {
                String raw = new String(payloadOriginal, StandardCharsets.UTF_8);
                if (!looksLikeJson(raw)) {
                    throw new IllegalArgumentException("--canonicalize-payload=jcs requires a valid JSON payload (object or array).");
                }
                String canonical = JsonCanonicalizerJcs.canonicalize(raw);
                payloadEffective = canonical.getBytes(StandardCharsets.UTF_8);
            }

            // --- 3) Signing-Input erzeugen ---
            byte[] signingInputBytes;
            String payloadB64 = null;
            boolean headerB64False = Boolean.FALSE.equals(ph.asObjectMap().get("b64"));

            if (headerB64False) {
                if ("compact".equalsIgnoreCase(outFormat) && !detached) {
                    throw new IllegalArgumentException("Compact + b64=false erfordert --detached (Compact kann keine Roh-Payload einbetten).");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                signingInputBytes = concat(left, payloadEffective);
            } else {
                payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadEffective);
                signingInputBytes = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            }

            // --- 3b) Artefakte: Payload-Text & Base64-Hash des Signing-Inputs ---
            writePayloadTextAndHashArtifacts(payloadEffective, signingInputBytes, outFile, alg);

            // --- 4) Private Key laden ---
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

            // --- 5) Signatur erzeugen ---
            byte[] sig = signJws(signingInputBytes, priv, alg);
            String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

            // --- 6) Ausgabe (Compact/JSON) ---
            String result;
            if ("compact".equalsIgnoreCase(outFormat)) {
                if (detached) {
                    result = protectedB64 + ".." + sigB64;
                } else {
                    if (headerB64False) {
                        throw new IllegalArgumentException("Compact eingebettet mit b64=false ist nicht zulässig. Nutze --detached oder JSON.");
                    }
                    result = protectedB64 + "." + payloadB64 + "." + sigB64;
                }
            } else if ("json".equalsIgnoreCase(outFormat)) {
                if (detached) {
                    result = """
                            {
                              "protected":"%s",
                              "signature":"%s"
                            }
                            """.formatted(protectedB64, sigB64).trim();
                } else {
                    if (headerB64False) {
                        String rawText = new String(payloadEffective, StandardCharsets.UTF_8);
                        String esc = jsonEscape(rawText);
                        result = """
                                {
                                  "payload":"%s",
                                  "protected":"%s",
                                  "signature":"%s"
                                }
                                """.formatted(esc, protectedB64, sigB64).trim();
                    } else {
                        result = """
                                {
                                  "payload":"%s",
                                  "protected":"%s",
                                  "signature":"%s"
                                }
                                """.formatted(payloadB64, protectedB64, sigB64).trim();
                    }
                }
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

    /* ====================== Artefakte ====================== */

    private static void writePayloadTextAndHashArtifacts(byte[] payloadEffective,
                                                         byte[] signingInputBytes,
                                                         Path outFile,
                                                         String alg) throws Exception {
        Path baseDir = outFile.toAbsolutePath().getParent();
        if (baseDir == null) baseDir = Path.of(".");
        String outName = outFile.getFileName().toString();

        Path json4SigPath = baseDir.resolve("JSON4Signature" + outName);
        Path hash4SigPath = baseDir.resolve("HASH4Signature" + outName);

        // a) Payload als Text (UTF-8). Bei Nicht-UTF-8 werden Ersatzzeichen verwendet.
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        String payloadText = dec.decode(java.nio.ByteBuffer.wrap(payloadEffective)).toString();
        Files.writeString(json4SigPath, payloadText, StandardCharsets.UTF_8);

        // b) Hash über den tatsächlichen Signing-Input → JAdES-konform Base64 (mit Padding)
        String digestAlg = switch (alg) {
            case "ES256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            case "ES512", "RS512", "PS512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };
        MessageDigest md = MessageDigest.getInstance(digestAlg);
        byte[] digest = md.digest(signingInputBytes);
        String digestB64 = Base64.getEncoder().encodeToString(digest); // Standard-Base64 mit Padding
        Files.writeString(hash4SigPath, digestB64 + System.lineSeparator(), StandardCharsets.UTF_8);

        System.out.println("Wrote JSON4Signature: " + json4SigPath);
        System.out.println("Wrote HASH4Signature: " + hash4SigPath);
    }

    /* ====================== Signaturalgorithmen ====================== */

    private static byte[] signJws(byte[] signingInput, PrivateKey key, String alg) throws Exception {
        switch (alg) {
            case "RS512": {
                Signature s = Signature.getInstance("SHA512withRSA");
                s.initSign(key); s.update(signingInput); return s.sign();
            }
            case "PS512": {
                Signature s = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"),
                        64, 1);
                s.setParameter(pss);
                s.initSign(key); s.update(signingInput); return s.sign();
            }
            case "ES256":
            case "ES384":
            case "ES512": {
                String jca = switch (alg) {
                    case "ES256" -> "SHA256withECDSA";
                    case "ES384" -> "SHA384withECDSA";
                    default -> "SHA512withECDSA";
                };
                Signature s = Signature.getInstance(jca);
                s.initSign(key); s.update(signingInput);
                byte[] derSig = s.sign();
                // JWS erwartet R||S (raw). Provider liefert meist DER → transcodieren:
                return EcdsaDer.transcodeDerToConcat(derSig, ecdsaFieldSizeBytes(alg));
            }
            default:
                throw new IllegalArgumentException("Unsupported alg: " + alg);
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

    /* ====================== Helpers ====================== */

    private static boolean looksLikeJson(String s) {
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) i++;
        if (i >= n) return false;
        char c = s.charAt(i);
        return c == '{' || c == '[';
    }

    private static String jsonEscape(String s) {
        return s.replace("\\","\\\\")
                .replace("\"","\\\"")
                .replace("\r","\\r")
                .replace("\n","\\n")
                .replace("\t","\\t");
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length); // ✅ korrekt
        return out;
    }

    private static String toHexUpper(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString().toUpperCase(Locale.ROOT);
    }
}


