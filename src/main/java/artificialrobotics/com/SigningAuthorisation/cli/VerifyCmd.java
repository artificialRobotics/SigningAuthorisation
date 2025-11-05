package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;
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

@CommandLine.Command(name = "verify", description = "Verify JWS/JAdES (crypto-only or eIDAS/DSS).")
public class VerifyCmd implements Runnable {

    @CommandLine.Option(names = "--mode", required = true, description = "crypto | eidas")
    String mode;

    @CommandLine.Option(names = "--alg", required = true, description = "RS512 | PS512 | ES256 | ES384 | ES512")
    String alg;

    @CommandLine.Option(names = "--in", required = true, description = "JWS input file (compact OR JSON serialization)")
    Path inFile;

    // Für crypto-only: Public Key oder Zertifikat angeben
    @CommandLine.Option(names = "--pub-dir", description = "Directory of public key / certificate")
    Path pubDir;

    @CommandLine.Option(names = "--pub-file", description = "File name of public key / certificate")
    String pubFile;

    // Detached / b64=false Unterstützung
    @CommandLine.Option(names = "--detached", description = "Treat input as detached JWS. Provide --payload for verification.")
    boolean detached;

    @CommandLine.Option(names = "--payload", description = "Detached payload file (raw bytes). Required for detached or b64=false.")
    Path payloadFile;

    // NEU: optionale Kanonisierung für die externe Payload-Datei
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

            // --- CRYPTO-ONLY VERIFIKATION ---
            // 1) Zerlegen: Compact oder JSON?
            String protectedB64;
            String payloadB64 = null;     // kann leer sein (detached)
            String signatureB64;

            if (isJsonSerialization(content)) {
                // JSON Serialization (single signature erwartet)
                protectedB64 = extractJsonValue(content, "\"protected\"");
                signatureB64 = extractJsonValue(content, "\"signature\"");
                // payload kann fehlen (detached) – nur nutzen, wenn vorhanden
                if (content.contains("\"payload\"")) {
                    payloadB64 = extractJsonValue(content, "\"payload\"");
                }
            } else {
                // Compact Serialization
                String[] parts = content.split("\\.", -1); // -1: leere Teile behalten
                if (parts.length != 3) throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
                protectedB64 = parts[0];
                payloadB64   = parts[1]; // kann leer sein, wenn detached
                signatureB64 = parts[2];
            }

            // 2) b64=false ermitteln (aus Protected Header)
            byte[] protectedJson = Base64.getUrlDecoder().decode(protectedB64);
            String protectedStr  = new String(protectedJson, StandardCharsets.UTF_8);
            boolean b64false = protectedStr.contains("\"b64\":false");

            // 3) Signing-Input bilden (RFC 7515 / RFC 7797)
            byte[] signingInput;
            if (b64false) {
                if (payloadFile == null) {
                    throw new IllegalArgumentException("b64=false erfordert --payload mit den ROH-Bytes der Nutzlast.");
                }
                byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
                byte[] raw  = loadDetachedPayloadPossiblyCanonicalized(); // NEU: ggf. JCS
                signingInput = concat(left, raw);
            } else {
                if (detached) {
                    // Detached: payloadB64 aus Datei erzeugen (ggf. nach JCS)
                    if (payloadFile == null) {
                        throw new IllegalArgumentException("detached erfordert --payload (für b64=true).");
                    }
                    byte[] raw = loadDetachedPayloadPossiblyCanonicalized(); // NEU: ggf. JCS
                    payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
                } else {
                    // eingebettet -> payloadB64 muss vorhanden sein
                    if (payloadB64 == null) {
                        throw new IllegalArgumentException("Eingebettete Signatur erwartet ein 'payload' im JWS.");
                    }
                }
                signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            }

            // 4) Signatur & Public Key laden
            byte[] sig = Base64.getUrlDecoder().decode(signatureB64);

            if (pubDir == null || pubFile == null) {
                throw new IllegalArgumentException("crypto mode benötigt --pub-dir und --pub-file (Public Key oder Zertifikat).");
            }

            PublicKey pub;
            try {
                // versucht PublicKey aus PEM/XML/HEX
                pub = PublicKeyFactory.load(pubDir, pubFile);
            } catch (Exception e) {
                // Fallback: Public Key aus Zertifikat extrahieren
                var cl = new PEMCertificateLoader(pubDir, pubFile);
                cl.load();
                if (cl.getCertificate() == null) {
                    throw new IllegalArgumentException("Konnte keinen Public Key laden (weder Key noch Zertifikat).", e);
                }
                pub = cl.getCertificate().getPublicKey();
            }

            // 5) Kryptografisch verifizieren
            boolean ok = verifyJws(signingInput, sig, pub, alg);
            System.out.println("VALID (crypto-only): " + ok);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== DSS/eIDAS-VERIFIKATION ====================== */

    private void verifyWithDss(String content) throws Exception {
        String jsonForDss = content;

        // DSS erwartet JSON Serialization; Compact ggf. on-the-fly in JSON verpacken
        if (!isJsonSerialization(content)) {
            String[] parts = content.split("\\.", -1);
            if (parts.length != 3) throw new IllegalArgumentException("Invalid compact JWS for DSS.");
            String protectedB64 = parts[0];
            String payloadB64   = parts[1];  // kann leer sein (detached)
            String signatureB64 = parts[2];

            // Für DSS-JSON: Wenn detached, lassen wir "payload" weg; sonst einfügen
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
        validator.setCertificateVerifier(new CommonCertificateVerifier()); // Basis; TSL/OCSP/CRL später konfigurieren

        // Detached-/b64=false-Handhabung: DSS kann mit detached Contents umgehen
        if (payloadFile != null) {
            byte[] raw = Files.readAllBytes(payloadFile);
            validator.setDetachedContents(List.of(new InMemoryDocument(raw)));
        }

        Reports reports = validator.validateDocument();
        System.out.println("VALID (DSS): " + reports.getSimpleReport().isValid("Zu ergaenzen"));
        System.out.println(reports.getSimpleReport().toString());
    }

    /* ====================== KRYPTOPFAD ====================== */

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
                // JWS liefert R||S (raw), viele Provider erwarten DER -> umwandeln:
                byte[] der = EcdsaConcatToDer.concatToDer(sig, ecdsaFieldSizeBytes(alg));
                return v.verify(der);
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

    /* ====================== HILFSFUNKTIONEN ====================== */

    private static boolean isJsonSerialization(String s) {
        // sehr einfache Heuristik: JSON-Serialization enthält "protected" und "signature" Felder
        return s.contains("\"protected\"") && s.contains("\"signature\"");
    }

    private static String extractJsonValue(String json, String keyWithQuotes) {
        // Minimalparser für einfache Strings:  "key":"value"
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

    /** Lädt die externe Payload-Datei und kanonisiert sie optional (JCS), wenn --canonicalize-payload=jcs gesetzt wurde. */
    private byte[] loadDetachedPayloadPossiblyCanonicalized() throws Exception {
        byte[] raw = Files.readAllBytes(payloadFile);
        boolean doCanonicalize = canonicalizePayload != null && canonicalizePayload.equalsIgnoreCase("jcs");
        if (!doCanonicalize) return raw;

        // Nur JSON-Dateien sind kanonisierbar – sicherstellen
        String asText = new String(raw, StandardCharsets.UTF_8);
        if (!looksLikeJson(asText)) {
            throw new IllegalArgumentException("--canonicalize-payload=jcs benötigt eine JSON-Payload-Datei (Object oder Array).");
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
