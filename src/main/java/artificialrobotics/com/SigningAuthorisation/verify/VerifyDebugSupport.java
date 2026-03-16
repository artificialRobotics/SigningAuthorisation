package artificialrobotics.com.SigningAuthorisation.verify;

import artificialrobotics.com.SigningAuthorisation.jose.JoseInputParser;
import artificialrobotics.com.SigningAuthorisation.cli.PayloadInputResolver;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.BooleanSupplier;

public final class VerifyDebugSupport {

    private final BooleanSupplier enabledSupplier;
    private final PayloadInputResolver payloadInputResolver = new PayloadInputResolver();

    public VerifyDebugSupport(BooleanSupplier enabledSupplier) {
        this.enabledSupplier = enabledSupplier;
    }

    private boolean enabled() {
        return enabledSupplier != null && enabledSupplier.getAsBoolean();
    }

    public void debug(String label, String value) {
        if (!enabled()) return;
        System.out.println("[DEBUG] " + label + ": " + value);
    }

    public void debugMultiline(String label, String value) {
        if (!enabled()) return;
        System.out.println("[DEBUG] " + label + ":");
        System.out.println(value);
    }

    public void debugPayload(byte[] payload, String label) throws Exception {
        if (!enabled() || payload == null) return;
        debug(label + " bytes", String.valueOf(payload.length));
        debug(label + " sha512 b64", sha512Base64(payload));
        debug(label + " first16 hex", toHexPrefix(payload, 16));
    }

    public void debugRawPayloadStructure(byte[] payload, String label) throws Exception {
        if (!enabled() || payload == null) return;

        debug(label + " utf8Bom", String.valueOf(hasUtf8Bom(payload)));
        debug(label + " endsWithCRLF", String.valueOf(endsWithCrLf(payload)));
        debug(label + " endsWithLFOnly", String.valueOf(endsWithLfOnly(payload)));
        debug(label + " endsWithCROnly", String.valueOf(endsWithCrOnly(payload)));
        debug(label + " sha256 b64", sha256Base64(payload));
        debug(label + " sha512 b64", sha512Base64(payload));
        debug(label + " first32 hex", toHexPrefix(payload, 32));
        debug(label + " last32 hex", toHexSuffix(payload, 32));
    }

    public void debugCertificate(String label, X509Certificate cert) throws Exception {
        if (!enabled() || cert == null) return;
        debug(label + " subject", cert.getSubjectX500Principal().getName());
        debug(label + " issuer", cert.getIssuerX500Principal().getName());
        debug(label + " serial", cert.getSerialNumber().toString(16));
        debug(label + " cert sha256", sha256Base64(cert.getEncoded()));
        debug(label + " pubkey sha256", sha256Base64(cert.getPublicKey().getEncoded()));
    }

    public void debugSigDHashComparisons(String protectedJson, byte[] payloadBytes, String label) throws Exception {
        if (!enabled() || protectedJson == null || payloadBytes == null) {
            return;
        }

        String sigDHashM = JoseInputParser.extractJsonValueLenient(protectedJson, "\"hashM\"");
        String sigDHashV = JoseInputParser.extractFirstStringFromJsonArray(protectedJson, "\"hashV\"");
        String sigDPar0 = JoseInputParser.extractFirstStringFromJsonArray(protectedJson, "\"pars\"");

        if (sigDHashM == null && sigDHashV == null) {
            debug(label + " sigD present", "false");
            return;
        }

        debug(label + " sigD present", "true");
        debug(label + " sigD.hashM", String.valueOf(sigDHashM));
        debug(label + " sigD.hashV", String.valueOf(sigDHashV));
        debug(label + " sigD.pars[0]", String.valueOf(sigDPar0));

        if (sigDHashV == null || sigDHashV.isBlank()) {
            return;
        }

        String payloadText = new String(payloadBytes, StandardCharsets.UTF_8);

        String rawSha512B64Url = sha512Base64Url(payloadBytes);
        String rawSha512B64 = sha512Base64(payloadBytes);
        debug(label + " sigD.compare raw.sha512.b64url", rawSha512B64Url);
        debug(label + " sigD.compare raw.sha512.b64", rawSha512B64);
        debug(label + " sigD.compare raw matches", String.valueOf(sigDHashV.equals(rawSha512B64Url)));

        String payloadB64UrlText = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes);
        debugHashCandidate(label, "payloadB64UrlText", payloadB64UrlText.getBytes(StandardCharsets.US_ASCII), sigDHashV);

        if (payloadInputResolver.looksLikeJson(payloadText)) {
            String minified = jsonMinify(payloadText);
            byte[] minifiedBytes = minified.getBytes(StandardCharsets.UTF_8);
            debugHashCandidate(label, "minified", minifiedBytes, sigDHashV);

            try {
                String jcs = JsonCanonicalizerJcs.canonicalize(payloadText);
                byte[] jcsBytes = jcs.getBytes(StandardCharsets.UTF_8);
                debugHashCandidate(label, "jcs", jcsBytes, sigDHashV);
            } catch (Exception e) {
                debug(label + " sigD.compare jcs", "exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }

            String lfNormalized = payloadText.replace("\r\n", "\n").replace('\r', '\n');
            debugHashCandidate(label, "lfNormalized", lfNormalized.getBytes(StandardCharsets.UTF_8), sigDHashV);

            String crlfNormalized = normalizeToCrLf(payloadText);
            debugHashCandidate(label, "crlfNormalized", crlfNormalized.getBytes(StandardCharsets.UTF_8), sigDHashV);
        } else {
            debug(label + " sigD.compare minified/jcs/lineNormalized", "skipped (payload not JSON)");
        }

        if (sigDPar0 != null) {
            debugHashCandidate(label, "sigD.pars[0]", sigDPar0.getBytes(StandardCharsets.UTF_8), sigDHashV);
            debugHashCandidate(label, "\"sigD.pars[0]\"", ("\"" + sigDPar0 + "\"").getBytes(StandardCharsets.UTF_8), sigDHashV);
            debugHashCandidate(label, "[\"sigD.pars[0]\"]", ("[\"" + sigDPar0 + "\"]").getBytes(StandardCharsets.UTF_8), sigDHashV);

            String parsArrayMin = "[\"" + sigDPar0 + "\"]";
            debugHashCandidate(label, "sigD.pars array json", parsArrayMin.getBytes(StandardCharsets.UTF_8), sigDHashV);

            debugHashCandidate(label, "sigD.pars[0]+\":\"+payload", (sigDPar0 + ":" + payloadText).getBytes(StandardCharsets.UTF_8), sigDHashV);
            debugHashCandidate(label, "sigD.pars[0]+LF+payload", (sigDPar0 + "\n" + payloadText).getBytes(StandardCharsets.UTF_8), sigDHashV);
            debugHashCandidate(label, "sigD.pars[0]+CRLF+payload", (sigDPar0 + "\r\n" + payloadText).getBytes(StandardCharsets.UTF_8), sigDHashV);
        }
    }

    public void debugRs512RecoveredDigest(PublicKey pub,
                                          byte[] signature,
                                          byte[] signingInput,
                                          byte[] externallyProvidedDigest,
                                          byte[] detachedPayloadRaw,
                                          String payloadB64,
                                          String protectedJson) throws Exception {
        if (!enabled()) return;

        if (!(pub instanceof RSAPublicKey rsaPub)) {
            debug("rs512 recovered digest", "skipped (public key is not RSA)");
            return;
        }

        byte[] em = rsaPkcs1RecoverEncodedMessage(signature, rsaPub);
        debug("rs512 recovered em bytes", String.valueOf(em.length));
        debug("rs512 recovered em first32 hex", toHexPrefix(em, 32));
        debug("rs512 recovered em last32 hex", toHexSuffix(em, 32));

        byte[] digestInfo = extractPkcs1v15DigestInfo(em);
        if (digestInfo == null) {
            debug("rs512 recovered digest", "could not parse PKCS#1 v1.5 DigestInfo");
            return;
        }

        debug("rs512 recovered digestInfo bytes", String.valueOf(digestInfo.length));
        debug("rs512 recovered digestInfo first32 hex", toHexPrefix(digestInfo, 32));

        byte[] recoveredSha512 = tryExtractSha512FromDigestInfo(digestInfo);
        if (recoveredSha512 == null) {
            debug("rs512 recovered digest", "DigestInfo is not SHA-512 or has unexpected format");
            return;
        }

        debug("rs512 recovered sha512 bytes", String.valueOf(recoveredSha512.length));
        debug("rs512 recovered sha512 b64", Base64.getEncoder().encodeToString(recoveredSha512));
        debug("rs512 recovered sha512 b64url", Base64.getUrlEncoder().withoutPadding().encodeToString(recoveredSha512));

        if (signingInput != null) {
            debugRecoveredDigestMatch("signingInput", recoveredSha512, MessageDigest.getInstance("SHA-512").digest(signingInput));
        }
        if (externallyProvidedDigest != null) {
            debugRecoveredDigestMatch("providedDigest", recoveredSha512, externallyProvidedDigest);
        }
        if (detachedPayloadRaw != null) {
            debugRecoveredDigestMatch("rawPayload", recoveredSha512, MessageDigest.getInstance("SHA-512").digest(detachedPayloadRaw));
        }
        if (payloadB64 != null) {
            debugRecoveredDigestMatch("payloadB64Ascii", recoveredSha512,
                    MessageDigest.getInstance("SHA-512").digest(payloadB64.getBytes(StandardCharsets.US_ASCII)));
        }
        if (protectedJson != null) {
            debugRecoveredDigestMatch("protectedJsonUtf8", recoveredSha512,
                    MessageDigest.getInstance("SHA-512").digest(protectedJson.getBytes(StandardCharsets.UTF_8)));

            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(protectedJson.getBytes(StandardCharsets.UTF_8));
            debugRecoveredDigestMatch("protectedB64Ascii", recoveredSha512,
                    MessageDigest.getInstance("SHA-512").digest(protectedB64.getBytes(StandardCharsets.US_ASCII)));
        }
    }

    public String providerList() {
        Provider[] providers = Security.getProviders();
        List<String> names = new ArrayList<>();
        for (Provider p : providers) {
            names.add(p.getName());
        }
        return String.join(", ", names);
    }

    public String abbreviate(String s, int maxLen) {
        if (s == null) return "null";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }

    private void debugHashCandidate(String label, String candidateName, byte[] candidateBytes, String expectedB64Url) throws Exception {
        String hash = sha512Base64Url(candidateBytes);
        debug(label + " sigD.compare " + candidateName + ".bytes", String.valueOf(candidateBytes.length));
        debug(label + " sigD.compare " + candidateName + ".sha512.b64url", hash);
        debug(label + " sigD.compare " + candidateName + " matches", String.valueOf(expectedB64Url.equals(hash)));
    }

    private void debugRecoveredDigestMatch(String candidateName, byte[] recovered, byte[] candidateDigest) {
        boolean match = MessageDigest.isEqual(recovered, candidateDigest);
        debug("rs512 recovered digest compare " + candidateName + ".b64",
                Base64.getEncoder().encodeToString(candidateDigest));
        debug("rs512 recovered digest compare " + candidateName + " matches", String.valueOf(match));
    }

    private static byte[] rsaPkcs1RecoverEncodedMessage(byte[] signature, RSAPublicKey pub) {
        int k = (pub.getModulus().bitLength() + 7) / 8;
        BigInteger s = new BigInteger(1, signature);
        BigInteger m = s.modPow(pub.getPublicExponent(), pub.getModulus());
        return toFixedLengthUnsigned(m, k);
    }

    private static byte[] extractPkcs1v15DigestInfo(byte[] em) {
        if (em == null || em.length < 11) {
            return null;
        }
        if (em[0] != 0x00 || em[1] != 0x01) {
            return null;
        }

        int i = 2;
        while (i < em.length && (em[i] & 0xFF) == 0xFF) {
            i++;
        }
        if (i >= em.length || em[i] != 0x00) {
            return null;
        }
        i++;

        if (i >= em.length) {
            return null;
        }
        return Arrays.copyOfRange(em, i, em.length);
    }

    private static byte[] tryExtractSha512FromDigestInfo(byte[] digestInfo) {
        byte[] prefix = new byte[]{
                0x30, 0x51,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                0x05, 0x00,
                0x04, 0x40
        };
        if (digestInfo == null || digestInfo.length != prefix.length + 64) {
            return null;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (digestInfo[i] != prefix[i]) {
                return null;
            }
        }
        return Arrays.copyOfRange(digestInfo, prefix.length, digestInfo.length);
    }

    private static byte[] toFixedLengthUnsigned(BigInteger x, int len) {
        byte[] src = x.toByteArray();
        if (src.length == len) {
            return src;
        }
        if (src.length == len + 1 && src[0] == 0x00) {
            return Arrays.copyOfRange(src, 1, src.length);
        }
        if (src.length < len) {
            byte[] out = new byte[len];
            System.arraycopy(src, 0, out, len - src.length, src.length);
            return out;
        }
        throw new IllegalArgumentException("Integer too large for target length.");
    }

    private static boolean hasUtf8Bom(byte[] data) {
        return data != null
                && data.length >= 3
                && (data[0] & 0xFF) == 0xEF
                && (data[1] & 0xFF) == 0xBB
                && (data[2] & 0xFF) == 0xBF;
    }

    private static boolean endsWithCrLf(byte[] data) {
        return data != null
                && data.length >= 2
                && data[data.length - 2] == 0x0D
                && data[data.length - 1] == 0x0A;
    }

    private static boolean endsWithLfOnly(byte[] data) {
        return data != null
                && data.length >= 1
                && data[data.length - 1] == 0x0A
                && !endsWithCrLf(data);
    }

    private static boolean endsWithCrOnly(byte[] data) {
        return data != null
                && data.length >= 1
                && data[data.length - 1] == 0x0D;
    }

    private static String sha512Base64(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }

    private static String sha512Base64Url(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String sha256Base64(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }

    private static String toHexPrefix(byte[] data, int maxBytes) {
        if (data == null) return "null";
        int len = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        if (data.length > maxBytes) {
            sb.append(" ...");
        }
        return sb.toString();
    }

    private static String toHexSuffix(byte[] data, int maxBytes) {
        if (data == null) return "null";
        int start = Math.max(0, data.length - maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < data.length; i++) {
            if (i > start) sb.append(' ');
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        if (start > 0) {
            return "... " + sb;
        }
        return sb.toString();
    }

    private static String jsonMinify(String s) {
        StringBuilder out = new StringBuilder(s.length());
        boolean inStr = false;
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                out.append(c);
                if (esc) {
                    esc = false;
                } else if (c == '\\') {
                    esc = true;
                } else if (c == '"') {
                    inStr = false;
                }
            } else {
                if (c == '"') {
                    inStr = true;
                    out.append(c);
                } else if (!Character.isWhitespace(c)) {
                    out.append(c);
                }
            }
        }
        return out.toString();
    }

    private static String normalizeToCrLf(String s) {
        String lf = s.replace("\r\n", "\n").replace('\r', '\n');
        return lf.replace("\n", "\r\n");
    }
}