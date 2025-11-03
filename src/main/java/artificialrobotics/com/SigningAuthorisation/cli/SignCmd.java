package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PrivateKeyFactory;
import artificialrobotics.com.SigningAuthorisation.certificates.CertificateLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.jose.ProtectedHeader;

import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@CommandLine.Command(
        name = "sign",
        description = "Sign payload to JWS (Compact or JSON). Supports detached and RFC 7797 (b64=false)."
)
public class SignCmd implements Runnable {

    @CommandLine.Option(names="--alg", required=true, description="RS512 | PS512 | ES256 | ES384 | ES512")
    String alg;

    @CommandLine.Option(names="--payload", required=true, description="Payload file; bytes are signed")
    Path payloadFile;

    @CommandLine.Option(names="--out-format", required=true, description="compact | json")
    String outFormat;

    // Private Key
    @CommandLine.Option(names="--key-dir", required=true) Path keyDir;
    @CommandLine.Option(names="--key-file", required=true) String keyFile;

    // Optional Zertifikatsangaben (für x5c) bzw. Referenz (x5u)
    @CommandLine.Option(names="--cert-dir") Path certDir;
    @CommandLine.Option(names="--cert-file") String certFile;
    @CommandLine.Option(names="--x5u") String x5u;

    // Detached / RFC 7797 (b64=false)
    @CommandLine.Option(names="--detached", description="Do not embed payload in the JWS (detached payload).")
    boolean detached;

    @CommandLine.Option(names="--b64false", description="Use RFC 7797 (unencoded payload); adds b64=false and crit:['b64'] to protected header.")
    boolean b64false;

    // NEU: Protected-Header-Overrides per Datei
    @CommandLine.Option(names="--protectedHeaderFile", description="JSON file with protected header overrides (merged).")
    Path protectedHeaderFile;

    // NEU: Einzelclaims (CLI) – werden nach Datei-Overrides angewandt
    @CommandLine.Option(names="--sub", description="Sets/overrides 'sub' claim in protected header.")
    String subClaim;

    @CommandLine.Option(names="--sigT", description="Sets/overrides 'sigT' claim (use 'CURRENT' for now-UTC).")
    String sigTClaim;

    @CommandLine.Option(names="--out", required=true, description="Output file for resulting JWS (compact or JSON)")
    Path outFile;

    @Override
    public void run() {
        try {
            new InitBC(); // Provider initialisieren (idempotent)

            // 1) Basis-Header aus CLI-Parametern
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("alg", alg);
            if (b64false) {
                base.put("b64", false); // ProtectedHeader setzt dann automatisch 'crit' -> 'b64'
            }
            if (x5u != null && !x5u.isBlank()) {
                base.put("x5u", x5u);
            }
            // x5c optional aus Datei laden
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

            // 2) ProtectedHeader aufbauen + Datei-Overrides einspielen
            ProtectedHeader ph = new ProtectedHeader(base);
            if (protectedHeaderFile != null) {
                String overridesJson = Files.readString(protectedHeaderFile, StandardCharsets.UTF_8);
                ph.applyOverridesJson(overridesJson); // 'crit' wird additiv gemerged; 'b64=false' pflegt 'crit'
            }

            // 3) Einzel-Claims (CLI) anwenden – haben höchste Priorität
            if (subClaim != null) {
                ph.put("sub", subClaim);    // fügt 'sub' automatisch in 'crit' ein
            }
            if (sigTClaim != null) {
                ph.put("sigT", sigTClaim);  // 'CURRENT' → aktuelle UTC; fügt 'sigT' automatisch in 'crit' ein
            }

            // 4) Protected-Header serialisieren (kompakt) und Base64URL-kodieren
            var b64u = Base64.getUrlEncoder().withoutPadding();
            String protectedB64 = b64u.encodeToString(ph.toCompactJson().getBytes(StandardCharsets.UTF_8));
            System.out.println(ph.toPrettyJson());

            // 5) Signing-Input erzeugen
            byte[] payloadRaw = Files.readAllBytes(payloadFile);
            byte[] signingInputBytes;
            String payloadB64 = null;

            boolean headerB64False = Boolean.FALSE.equals(ph.asObjectMap().get("b64"));

            if (headerB64False) {
                // RFC 7797: compact + b64=false nur mit detached sinnvoll/erlaubt
                if ("compact".equalsIgnoreCase(outFormat) && !detached) {
                    throw new IllegalArgumentException("Compact + b64=false erfordert --detached (Compact kann keine Roh-Payload einbetten).");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                signingInputBytes = concat(left, payloadRaw);
            } else {
                payloadB64 = b64u.encodeToString(payloadRaw);
                signingInputBytes = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            }

            // 6) Signatur erzeugen
            PrivateKey priv = PrivateKeyFactory.load(keyDir, keyFile);
            byte[] sig = signJws(signingInputBytes, priv, alg);
            String sigB64 = b64u.encodeToString(sig);

            // 7) Ausgabe zusammenbauen
            String result;
            if ("compact".equalsIgnoreCase(outFormat)) {
                if (detached) {
                    result = protectedB64 + ".." + sigB64; // detached: payload ausgelassen
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
                        // Eingebettet + b64=false: roher Text (nur sinnvoll für Textpayload)
                        String rawText = Files.readString(payloadFile, StandardCharsets.UTF_8);
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

            // 8) Schreiben
            Files.writeString(outFile, result, StandardCharsets.UTF_8);
            System.out.println("Wrote: " + outFile.toAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== Signaturalgorithmen ====================== */

    private static byte[] signJws(byte[] signingInput, PrivateKey key, String alg) throws Exception {
        switch (alg) {
            case "RS512": {
                Signature s = Signature.getInstance("SHA512withRSA");
                s.initSign(key);
                s.update(signingInput);
                return s.sign();
            }
            case "PS512": {
                Signature s = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"),
                        64, 1);
                s.setParameter(pss);
                s.initSign(key);
                s.update(signingInput);
                return s.sign();
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
                s.initSign(key);
                s.update(signingInput);
                byte[] derSig = s.sign();
                // JWS verlangt R||S (raw). Provider liefert i. d. R. DER -> transcodieren:
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
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
