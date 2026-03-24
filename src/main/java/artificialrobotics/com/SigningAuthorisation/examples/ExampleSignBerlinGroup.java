package artificialrobotics.com.SigningAuthorisation.examples;

import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Example: Detached signature in the Berlin Group wrapper using PS512 OR ES512,
 * with a strict "pre-hash" model (separating hashing and signing to enable private key processing via HSM).
 *
 * Step-by-step flow:
 *   1) Resolve "sigT":"CURRENT" in protected header (UTC, ISO-8601, seconds precision, trailing 'Z')
 *   2) Automatically derive and inject "iat" (NumericDate / epoch seconds):
 *        - from sigT, if present
 *        - otherwise from current UTC time
 *   3) Embed certificate into protected header as:
 *        - x5c[0]    = base64 DER (NOT base64url)
 *        - x5t#S256  = Base64URL(SHA-256(cert DER))
 *   4) Protected header: compact JSON -> Base64URL (RFC 7515)
 *   5) Payload handling:
 *        - if "canonAlg":"JCS" is present in the protected header:
 *              canonicalize payload via JCS -> Base64URL
 *        - if no "canonAlg" is present:
 *              use payload as given -> Base64URL
 *   6) Build signing input: ASCII(protectedB64 + "." + payloadB64)
 *   7) Compute SHA-512 over signing input  => messageToSign (pre-hash)
 *   8) Sign messageToSign depending on "alg":
 *        - PS512: RAWRSASSA-PSS over SHA-512 digest (no internal hashing)
 *        - ES512: NONEwithECDSA over SHA-512 digest (no internal hashing)
 *   9) IMPORTANT for ES512:
 *        - JCA/BC returns DER encoded ECDSA signature
 *        - JWS requires JOSE raw R||S
 *        - therefore DER is transcoded to raw R||S before Base64URL encoding
 *  10) Return Berlin Group wrapper JSON with "protected" and "signature"
 *
 * Notes:
 *   - This example intentionally keeps the project’s pre-hash approach.
 *   - For ES512, the final JWS signature representation MUST be raw R||S, not DER,
 *     otherwise standard JOSE/JAdES validators (for example DSS) will reject it.
 *   - x5c is used consistently in the examples. x5t#S256 is added automatically as an additional
 *     certificate reference derived from the same certificate.
 *   - Payload canonicalization is no longer assumed implicitly. It is executed only if the
 *     protected header contains "canonAlg":"JCS".
 */
public class ExampleSignBerlinGroup {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Pattern SIGT_CURRENT =
            Pattern.compile("\"sigT\"\\s*:\\s*\"CURRENT\"", Pattern.CASE_INSENSITIVE);

    private static final Pattern ALG_PATTERN =
            Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");

    private static final Pattern SIGT_PATTERN =
            Pattern.compile("\"sigT\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    private static final Pattern IAT_PATTERN =
            Pattern.compile("\"iat\"\\s*:\\s*(\\d+)");

    private static final Pattern CANON_ALG_PATTERN =
            Pattern.compile("\"canonAlg\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    /** Signing registry (no switch required in the main flow). */
    private static final Map<String, DigestSigner> SIGNERS = new HashMap<>();
    static {
        SIGNERS.put("PS512", ExampleSignBerlinGroup::signPreHashedPS512);
        SIGNERS.put("ES512", ExampleSignBerlinGroup::signPreHashedES512NoHash);
    }

    @FunctionalInterface
    private interface DigestSigner {
        String sign(String pemPrivateKeyPkcs8OrPkcs1OrEcPkcs8, byte[] sha512Digest) throws Exception;
    }

    /* ---------- Protected header to Base64URL ---------- */
    public static String protectedHeaderToBase64Url(String prettyJsonProtectedHeaderUtcNow, String pemCertificate) throws Exception {
        String enriched = enrichProtectedHeader(prettyJsonProtectedHeaderUtcNow, pemCertificate);
        String compact = jsonMinify(enriched);
        byte[] utf8 = compact.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
    }

    /* ---------- Payload handling to Base64URL ---------- */
    public static String payloadJsonToBase64Url(String jsonPayloadPrettyOrCompact, String protectedHeaderJson) {
        String canonAlg = extractCanonAlgFromProtectedHeaderJson(protectedHeaderJson);

        String payloadToEncode;
        if (canonAlg == null || canonAlg.isBlank()) {
            payloadToEncode = jsonPayloadPrettyOrCompact;
        } else { //when canonAlg is set, do canonicalize the payload before signing
            payloadToEncode = JsonCanonicalizerJcs.canonicalize(jsonPayloadPrettyOrCompact);
        }

        byte[] utf8 = payloadToEncode.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
    }

    /* ---------- Signing input + SHA-512 digest ---------- */
    public static SigningInput computeSigningInputAndHash(String protectedB64, String payloadB64) throws Exception {
        byte[] signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] digest = md.digest(signingInput);
        String digestB64 = Base64.getEncoder().encodeToString(digest);
        return new SigningInput(signingInput, digest, digestB64);
    }

    /* ---------- Sign digest (PS512) ---------- */
    public static String signPreHashedPS512(String pemPrivateKeyPkcs8OrPkcs1, byte[] sha512Digest) throws Exception {
        PrivateKey jcaPriv = parseRsaPrivateKeyFromPem(pemPrivateKeyPkcs8OrPkcs1);

        java.security.Signature s = java.security.Signature.getInstance("RAWRSASSA-PSS", "BC");
        java.security.spec.PSSParameterSpec pss = new java.security.spec.PSSParameterSpec(
                "SHA-512", "MGF1",
                new java.security.spec.MGF1ParameterSpec("SHA-512"),
                64, 1
        );
        s.setParameter(pss);
        s.initSign(jcaPriv, new SecureRandom());

        // Pre-hash input: pass SHA-512(signingInput) without additional hashing
        s.update(sha512Digest);
        byte[] sig = s.sign();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }

    /* ---------- Sign digest (ES512, no internal hashing) ---------- */
    /**
     * ES512 signing over the SHA-512 digest WITHOUT internal hashing.
     *
     * Important:
     *   - NONEwithECDSA (BC) returns a DER encoded ASN.1 signature.
     *   - JWS/JAdES requires JOSE raw R||S encoding.
     *   - Therefore DER is transcoded to raw R||S (132 bytes for P-521) before Base64URL encoding.
     *
     * Requires an EC P-521 private key in PKCS#8 ("BEGIN PRIVATE KEY").
     */
    public static String signPreHashedES512NoHash(String pemEcPrivateKeyPkcs8, byte[] sha512Digest) throws Exception {
        PrivateKey jcaPriv = parseEcPrivateKeyFromPemPkcs8(pemEcPrivateKeyPkcs8);

        var s = java.security.Signature.getInstance("NONEwithECDSA", "BC");
        s.initSign(jcaPriv, new SecureRandom());
        s.update(sha512Digest);
        byte[] sigDer = s.sign();

        byte[] sigJose = transcodeDerToConcat(sigDer, 66);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigJose);
    }

    /**
     * Orchestrate detached signature creation and return Berlin Group wrapper JSON.
     *
     * @param protectedHeaderPrettyJson protected header in pretty JSON, may contain "sigT":"CURRENT"
     * @param payloadJson               business payload JSON; canonicalization is only performed if the
     *                                 protected header contains "canonAlg":"JCS"
     * @param privateKeyPem             private key PEM:
     *                                 - for PS512: RSA PKCS#8 ("PRIVATE KEY") or PKCS#1 ("RSA PRIVATE KEY")
     *                                 - for ES512: EC P-521 PKCS#8 ("PRIVATE KEY")
     * @param pemCertificate            X.509 certificate PEM ("BEGIN CERTIFICATE")
     * @return pretty Berlin Group wrapper JSON with "protected" and "signature"
     */
    public static String signDetachedBerlinGroup(
            String protectedHeaderPrettyJson,
            String payloadJson,
            String privateKeyPem,
            String pemCertificate
    ) throws Exception {

        // 1-3) Resolve sigT, derive iat, inject x5c and x5t#S256
        String enrichedHeader = enrichProtectedHeader(protectedHeaderPrettyJson, pemCertificate);

        // 4) Compact + Base64URL encode the protected header
        String compactHeader = jsonMinify(enrichedHeader);
        String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(compactHeader.getBytes(StandardCharsets.UTF_8));

        // 5) Payload handling depending on canonAlg in the protected header
        String payloadB64 = payloadJsonToBase64Url(payloadJson, enrichedHeader);

        // 6 + 7) Compute signing input + SHA-512 digest
        SigningInput si = computeSigningInputAndHash(protectedB64, payloadB64);

        // 8) Read alg from protected header JSON and sign accordingly
        String alg = extractAlgFromProtectedHeaderJson(enrichedHeader);
        if (alg == null || alg.isEmpty()) {
            throw new IllegalArgumentException("Missing or empty 'alg' claim in protected header.");
        }

        DigestSigner signer = SIGNERS.get(alg);
        if (signer == null) {
            throw new IllegalArgumentException("Unsupported alg in protected header: " + alg);
        }

        String sigB64 = signer.sign(privateKeyPem, si.digestSha512);

        // 9) Berlin Group wrapper (detached)
        return """
                {
                  "signatureData": {
                    "protected": "%s",
                    "signature": "%s"
                  }
                }
                """.formatted(protectedB64, sigB64).trim();
    }

    /* ================= Helper types & utilities ================= */

    public static final class SigningInput {
        public final byte[] signingInput;
        public final byte[] digestSha512;
        public final String digestBase64;

        public SigningInput(byte[] signingInput, byte[] digestSha512, String digestBase64) {
            this.signingInput = signingInput;
            this.digestSha512 = digestSha512;
            this.digestBase64 = digestBase64;
        }
    }

    /**
     * Enrich protected header by:
     *  - resolving sigT CURRENT
     *  - injecting iat if absent
     *  - injecting x5c if absent
     *  - injecting x5t#S256 if absent
     */
    private static String enrichProtectedHeader(String headerPretty, String pemCertificate) throws Exception {
        String withResolvedSigT = resolveSigTCurrentUtc(headerPretty);
        String withIat = injectIatIntoProtectedHeaderJson(withResolvedSigT);
        byte[] certDer = parseCertificateDerFromPem(pemCertificate);
        String certDerB64 = Base64.getEncoder().encodeToString(certDer);
        String withX5c = injectX5cIntoProtectedHeaderJson(withIat, certDerB64);
        String x5tS256 = base64UrlSha256(certDer);
        return injectX5tS256IntoProtectedHeaderJson(withX5c, x5tS256);
    }

    private static String resolveSigTCurrentUtc(String headerPretty) {
        String isoZ = Instant.now()
                .truncatedTo(ChronoUnit.SECONDS)
                .toString();
        Matcher m = SIGT_CURRENT.matcher(headerPretty);
        // make sigT and iat equal if given, for Baseline-B iat only should be used
        return m.replaceAll("\"sigT\":\"" + isoZ + "\"");
    }

    /**
     * Automatically derive and inject iat if not already present.
     * Rules:
     *  - if sigT exists, derive iat = epochSeconds(sigT)
     *  - otherwise use current UTC epoch seconds
     */
    private static String injectIatIntoProtectedHeaderJson(String headerJson) {
        if (IAT_PATTERN.matcher(headerJson).find()) {
            return headerJson;
        }

        long iat;
        Matcher sigTM = SIGT_PATTERN.matcher(headerJson);
        if (sigTM.find()) {
            String sigT = sigTM.group(1);
            try {
                iat = Instant.parse(sigT).getEpochSecond();
            } catch (Exception e) {
                throw new IllegalArgumentException("Could not derive iat from sigT: " + sigT, e);
            }
        } else {
            iat = Instant.now().getEpochSecond();
        }

        return injectSimpleNumberClaim(headerJson, "iat", iat);
    }

    /**
     * Produce a compact JSON representation of a JSON object by removing all
     * insignificant whitespace outside of string literals.
     *
     * Normative context:
     *   - RFC 7515 (JWS) requires the protected header to be a UTF-8 encoded JSON object
     *     which is Base64URL-encoded exactly as provided by the signer.
     *   - JSON itself (RFC 8259) defines whitespace as insignificant outside of string values.
     *
     * Important:
     *   - This is NOT a JSON canonicalization algorithm.
     *   - No reordering of object members is performed.
     *   - No normalization of numbers or Unicode is performed.
     */
    private static String jsonMinify(String s) {
        StringBuilder out = new StringBuilder(s.length());
        boolean inStr = false, esc = false;
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

    private static byte[] parseCertificateDerFromPem(String pemCert) throws Exception {
        PemObject po = readPem(pemCert);
        if (!"CERTIFICATE".equals(po.getType())) {
            throw new IllegalArgumentException("Expected PEM CERTIFICATE, got: " + po.getType());
        }
        return po.getContent();
    }

    private static String injectX5cIntoProtectedHeaderJson(String headerJson, String certDerBase64) {
        if (headerJson.contains("\"x5c\"")) {
            return headerJson;
        }

        int end = headerJson.lastIndexOf('}');
        if (end < 0) throw new IllegalArgumentException("Invalid JSON: no closing '}'");

        int start = headerJson.indexOf('{');
        if (start < 0 || start > end) throw new IllegalArgumentException("Invalid JSON: no opening '{'");
        boolean emptyObject = headerJson.substring(start + 1, end).trim().isEmpty();

        String insertion = (emptyObject ? "" : ",") + "\"x5c\":[\"" + certDerBase64 + "\"]";
        return headerJson.substring(0, end) + insertion + headerJson.substring(end);
    }

    private static String injectX5tS256IntoProtectedHeaderJson(String headerJson, String x5tS256) {
        if (headerJson.contains("\"x5t#S256\"")) {
            return headerJson;
        }

        int end = headerJson.lastIndexOf('}');
        if (end < 0) throw new IllegalArgumentException("Invalid JSON: no closing '}'");

        int start = headerJson.indexOf('{');
        if (start < 0 || start > end) throw new IllegalArgumentException("Invalid JSON: no opening '{'");
        boolean emptyObject = headerJson.substring(start + 1, end).trim().isEmpty();

        String insertion = (emptyObject ? "" : ",") + "\"x5t#S256\":\"" + x5tS256 + "\"";
        return headerJson.substring(0, end) + insertion + headerJson.substring(end);
    }

    private static String injectSimpleNumberClaim(String headerJson, String claimName, long value) {
        int end = headerJson.lastIndexOf('}');
        if (end < 0) throw new IllegalArgumentException("Invalid JSON: no closing '}'");

        int start = headerJson.indexOf('{');
        if (start < 0 || start > end) throw new IllegalArgumentException("Invalid JSON: no opening '{'");
        boolean emptyObject = headerJson.substring(start + 1, end).trim().isEmpty();

        String insertion = (emptyObject ? "" : ",") + "\"" + claimName + "\":" + value;
        return headerJson.substring(0, end) + insertion + headerJson.substring(end);
    }

    private static String extractAlgFromProtectedHeaderJson(String protectedHeaderJson) {
        Matcher m = ALG_PATTERN.matcher(protectedHeaderJson);
        return m.find() ? m.group(1) : null;
    }

    private static String extractCanonAlgFromProtectedHeaderJson(String protectedHeaderJson) {
        Matcher m = CANON_ALG_PATTERN.matcher(protectedHeaderJson);
        return m.find() ? m.group(1) : null;
    }

    private static String base64UrlSha256(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static PrivateKey parseRsaPrivateKeyFromPem(String pem) throws Exception {
        PemObject po = readPem(pem);
        String type = po.getType();
        byte[] content = po.getContent();

        if ("PRIVATE KEY".equals(type) || "ENCRYPTED PRIVATE KEY".equals(type)) {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(content));
        } else if ("RSA PRIVATE KEY".equals(type)) {
            byte[] pkcs8 = wrapPkcs1ToPkcs8(content);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } else {
            throw new IllegalArgumentException("Unsupported PEM type for RSA key: " + type);
        }
    }

    private static PrivateKey parseEcPrivateKeyFromPemPkcs8(String pem) throws Exception {
        PemObject po = readPem(pem);
        String type = po.getType();
        byte[] content = po.getContent();

        if (!"PRIVATE KEY".equals(type)) {
            throw new IllegalArgumentException("Unsupported PEM type for EC key in this example: " + type
                    + " (expected: PRIVATE KEY / PKCS#8)");
        }
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(content));
    }

    private static PemObject readPem(String pem) throws IOException {
        try (Reader r = new StringReader(pem); PemReader pr = new PemReader(r)) {
            PemObject po = pr.readPemObject();
            if (po == null) throw new IllegalArgumentException("No PEM object found");
            return po;
        }
    }

    /* ---- ECDSA DER -> JOSE raw R||S ---- */

    /**
     * Converts ASN.1 DER encoded ECDSA signature into JOSE raw R||S format.
     *
     * For ES512 / P-521:
     *   - R = 66 bytes
     *   - S = 66 bytes
     *   - output = 132 bytes
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

    /* ---- Minimal DER helpers for the PKCS#1→PKCS#8 wrapper ---- */

    private static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1Der) {
        String algIdHex = "300D06092A864886F70D0101010500";
        byte[] algId = hexToBytes(algIdHex);

        byte[] version = new byte[] { 0x02, 0x01, 0x00 };
        byte[] pkcs1Octet = derOctetString(pkcs1Der);
        byte[] body = concat(version, algId, pkcs1Octet);
        return derSequence(body);
    }

    private static byte[] derOctetString(byte[] val) {
        byte[] len = derLen(val.length);
        byte[] out = new byte[1 + len.length + val.length];
        out[0] = 0x04;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(val, 0, out, 1 + len.length, val.length);
        return out;
    }

    private static byte[] derSequence(byte[] body) {
        byte[] len = derLen(body.length);
        byte[] out = new byte[1 + len.length + body.length];
        out[0] = 0x30;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(body, 0, out, 1 + len.length, body.length);
        return out;
    }

    private static byte[] derLen(int length) {
        if (length < 128) return new byte[] { (byte) length };
        int tmp = length, bytes = 0;
        while (tmp > 0) {
            bytes++;
            tmp >>= 8;
        }
        byte[] out = new byte[1 + bytes];
        out[0] = (byte) (0x80 | bytes);
        for (int i = bytes; i > 0; i--) {
            out[i] = (byte) (length & 0xFF);
            length >>= 8;
        }
        return out;
    }

    private static byte[] concat(byte[]... arrs) {
        int n = 0, off = 0;
        for (byte[] a : arrs) n += a.length;
        byte[] out = new byte[n];
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, off, a.length);
            off += a.length;
        }
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        String h = hex.replaceAll("\\s+", "");
        if ((h.length() & 1) != 0) throw new IllegalArgumentException("Odd-length hex: " + hex);
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(h.charAt(2 * i), 16);
            int lo = Character.digit(h.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid hex at pos " + (2 * i));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /* =========================== Demo =========================== */

    /**
     * Demo prints a Berlin Group wrapper. Switch alg in header to "PS512" or "ES512".
     *
     * IMPORTANT for ES512:
     *   - Provide an EC P-521 PKCS#8 private key (BEGIN PRIVATE KEY) matching the certificate.
     *   - The final JWS signature is emitted in JOSE raw R||S format.
     *
     * IMPORTANT for canonAlg:
     *   - Payload canonicalization is only executed if the protected header explicitly contains
     *     "canonAlg":"http://json-canonicalization.org/algorithm" or "JCS".
     *   - If canonAlg is omitted, the payload is used as provided.
     */
    public static void main(String[] args) throws Exception {

        String payloadJson = """
{
 "amount": "10.50",
 "currency": "EUR",
 "debtor": {"iban":"DE02120300000000202051"},
 "creditor": {"iban":"DE75512108001245126199"},
 "remittanceInformation": "BG-Sample with .:_-äüöß@€"
}
                """;


        String headerPretty = """
                {
                  "alg": "PS512",
                  "sub": "aPaymentResID",
                  "canonAlg": "http://json-canonicalization.org/algorithm"
                }
                """;


// choose one of the following sign algorithm and keep header "alg" above in headerPretty consistent with the selected key/certificate


        // a) PS512: RSA private key (PKCS#8 or PKCS#1)
        String pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
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
Qz7SYrg06Cfx/JlNqM/DpP5K
-----END PRIVATE KEY-----
                """;

        String pemCertificate = """
-----BEGIN CERTIFICATE-----
MIIFJjCCA1qgAwIBAgIUGnAk7/vw9BseUNGJBeXgyi4XhFAwQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgMFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgMF
AKIDAgFAMGgxCzAJBgNVBAYTAkRFMRQwEgYDVQQKDAtNdXN0ZXIgR21iSDEUMBIG
A1UEAwwLTXVzdGVyIEdtYkgxEzARBgNVBAsMClBheW1lbnRIdWIxGDAWBgNVBGEM
D05UUkRFLUhSQjEyMzQ1NjAeFw0yNjAyMDExNzQ0NTVaFw0zNjAxMzAxNzQ0NTVa
MGgxCzAJBgNVBAYTAkRFMRQwEgYDVQQKDAtNdXN0ZXIgR21iSDEUMBIGA1UEAwwL
TXVzdGVyIEdtYkgxEzARBgNVBAsMClBheW1lbnRIdWIxGDAWBgNVBGEMD05UUkRF
LUhSQjEyMzQ1NjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANG18XuI
n45++MwpDxcS3pU4KXfCCzYj01ksZg4Cwhm5WMApkuBa8S9QkXDJfpudU+LqhK+a
segvtFmGddQ2uXOAZRAcX9mRtKuYJuJa8GEvbih45pLrtCPKmESqo9A91yVYiUy4
6aP7i0XkaE68ytNofISlx4MgFKwXPW+s2H7WfO/aQDLacPWQasgtkisLc5hzBwL3
dX6vEnMeA0GAQd6GY8/itAof3U+Sq2uMRd9RFbI2tOdXXMsul7hp34AH7FjukSCg
0eQxOjj62T3kJ6cJOfB1acxivqHTfnHoyyayKrkK95u/1ZVqgjycV6/175SSTofX
ma/VgSNz02CEoJ+DlR4nKj8ki+WQi7Ao8O3wbUtFl4nHReQ1F3hWNkmjM9POzGbv
osgbSbPYo1cQ/Nbvln9QxFpw5bUcInAxWmvnLRtE2yfg2/Ib+48+Cjgu5FtEokoH
iLnthFpQEM7Ye/Lwza46IDa4KqpjGFLDdTcJwjt7w7vt+TImlv+SYmAtmwIDAQAB
o2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQUnYmY
kU/8Y70SfANThVe2AiCSy5kwHwYDVR0jBBgwFoAUnYmYkU/8Y70SfANThVe2AiCS
y5kwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgMFAKEcMBoGCSqGSIb3DQEB
CDANBglghkgBZQMEAgMFAKIDAgFAA4IBgQAil8MBlm9ioQEfX/ml4IsGe4GWh4oK
/apEm7DvugG1fItxx/RCHs4eobCCYvA5ZPeE0+ieAOc3SvVRDgF10CosKtOFQc3n
zA0ALvjJybMvUTqJ/n7aNa6hSXOFiV8Hr4R1ObdNpOQxdVNDbJSysLm63XY86Vun
WpoxnwTuoJbpGXv43WBl+r25RYtU5+x+1PZ2kzxQEYrSKU78Omvdm2uTwA7CtE8m
0ukDEFTzYIXFNAmKXuC5Zt5NUtYxdsQItaJzQ88oMMryYTX1KLE2esCgu5/tQEku
k++tAzwDf+wFsP8ftvN813kSjrAnxG+9nHW1eDeZI2VAqdHZ4n/9leUug1nzChv4
uftQms0rurSbv0F5AjgfaieGOyet+8kaRaW8NWa6MAXxfI+tK6ChVa2SlOFAnTQ2
7h08jgJTsMD+xMKPzqwUcMIeswHhYUkxstOsf959FfG0KEnt3goUm3e7sCM6x+9o
h1U8MIKqfcRFVoAYOiUUSBy7luXdgKMWpXs=
-----END CERTIFICATE-----
                """;


   /*
     // b) ES512: EC P-521 PKCS#8 private key
        String pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA121jtgtb2xKFQC47
PnmFJph33uUoP8sYPiWqEX7jBBTj87nVZdAx4QTigUC69v0rNtLHFAVgUXnqFT64
5gkofRChgYkDgYYABADKlOJ+zrMRnjkA4X4Ra4Bqy/LMtto8a/AfbQfC+oUvmpHQ
pgwNnPvdhQzJ3cl+gBBwgLCbo9fIRe5DffiLm67fdQEXhPwDVK0e/cFBeSyPEpNf
7lnZ9AXwxabLpKSgFDsRVJAEYzCcQFseeh+h8t0MCdDQc9ZfhsmswaM7oyoOuv5K
sg==
-----END PRIVATE KEY-----
                """;

        String pemCertificate = """
-----BEGIN CERTIFICATE-----
MIICujCCAhugAwIBAgIUDd+gAMlWzLL+T2bbksfx/ZoqYv0wCgYIKoZIzj0EAwQw
aDELMAkGA1UEBhMCREUxFDASBgNVBAoMC011c3RlciBHbWJIMRQwEgYDVQQDDAtN
dXN0ZXIgR21iSDETMBEGA1UECwwKUGF5bWVudEh1YjEYMBYGA1UEYQwPTlRSREUt
SFJCMTIzNDU2MB4XDTI2MDIwMTE3NDQ1NloXDTM2MDEzMDE3NDQ1NlowaDELMAkG
A1UEBhMCREUxFDASBgNVBAoMC011c3RlciBHbWJIMRQwEgYDVQQDDAtNdXN0ZXIg
R21iSDETMBEGA1UECwwKUGF5bWVudEh1YjEYMBYGA1UEYQwPTlRSREUtSFJCMTIz
NDU2MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAypTifs6zEZ45AOF+EWuAasvy
zLbaPGvwH20HwvqFL5qR0KYMDZz73YUMyd3JfoAQcICwm6PXyEXuQ334i5uu33UB
F4T8A1StHv3BQXksjxKTX+5Z2fQF8MWmy6SkoBQ7EVSQBGMwnEBbHnofofLdDAnQ
0HPWX4bJrMGjO6MqDrr+SrKjYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
AgbAMB0GA1UdDgQWBBT46grmOA45o1JJuHQ4YROjlEfiaTAfBgNVHSMEGDAWgBT4
6grmOA45o1JJuHQ4YROjlEfiaTAKBggqhkjOPQQDBAOBjAAwgYgCQgDfUGXT6rqV
LvSUNWEE9LD6V1eVz4/QD7AdcFi2NHdVWFzePa6ufQT1B0X6x0RoBPVnYZlloNXA
B9gLunYXRukXDQJCAJkCrcW4gd6jNNuNZ0SzrGLtSaifV075pBeGKNLAjX67p/Fz
9RYgP/ycOmbB6lxJ3KCT1MTBt4HxFbNaYhI/tIjP
-----END CERTIFICATE-----
                """;
    */

        String bg = signDetachedBerlinGroup(headerPretty, payloadJson, pemPrivateKey, pemCertificate);
        System.out.println(bg);
    }
}