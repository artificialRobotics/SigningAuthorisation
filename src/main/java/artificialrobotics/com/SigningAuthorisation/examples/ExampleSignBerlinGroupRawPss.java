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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Example: Detached signature in the Berlin Group wrapper using PS512 OR ES512,
 * with a strict "pre-hash" model (separating hashing and signing to enable private key processing via HSM).
 *
 * Step-by-step flow (kept comparable to the verify-class):
 *   1) Resolve "sigT":"CURRENT" in protected header (UTC, ISO-8601, seconds precision, trailing 'Z')
 *   2) Embed certificate into protected header as x5c[0] (base64 DER; NOT base64url)
 *   3) Protected header: compact JSON -> Base64URL (RFC 7515)
 *   4) Payload canonicalization via JCS -> Base64URL
 *   5) Build signing input: ASCII(protectedB64 + "." + payloadB64)
 *   6) Compute SHA-512 over signing input  => messageToSign (pre-hash)
 *   7) Sign messageToSign depending on "alg":
 *        - PS512: RAWRSASSA-PSS over SHA-512 digest (no internal hashing)
 *        - ES512: NONEwithECDSA over SHA-512 digest (no internal hashing)
 *   8) Return Berlin Group wrapper JSON with "protected" and "signature"
 *
 * Notes:
 *   - For ES512 we intentionally use NONEwithECDSA (BC) to disable internal hashing,
 *     matching the verifier which verifies ES512 over the digest without hashing.
 *   - For ES512, the signature bytes are DER encoded (ASN.1 SEQUENCE r,s) as produced by JCA/BC.
 */
public class ExampleSignBerlinGroupRawPss {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Pattern SIGT_CURRENT =
            Pattern.compile("\"sigT\"\\s*:\\s*\"CURRENT\"", Pattern.CASE_INSENSITIVE);

    private static final Pattern ALG_PATTERN =
            Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");

    /** Signing registry (no switch required in the main flow). */
    private static final Map<String, DigestSigner> SIGNERS = new HashMap<>();
    static {
        SIGNERS.put("PS512", ExampleSignBerlinGroupRawPss::signPreHashedPS512);
        SIGNERS.put("ES512", ExampleSignBerlinGroupRawPss::signPreHashedES512NoHash);
    }

    @FunctionalInterface
    private interface DigestSigner {
        String sign(String pemPrivateKeyPkcs8OrPkcs1OrEcPkcs8, byte[] sha512Digest) throws Exception;
    }

    
    /* ---------- Protected header to Base64URL ---------- */
    public static String protectedHeaderToBase64Url(String prettyJsonProtectedHeaderUtcNow) {
        String withSigT = resolveSigTCurrentUtc(prettyJsonProtectedHeaderUtcNow);
        String compact = jsonMinify(withSigT);
        byte[] utf8 = compact.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
    }
    

    /* ---------- Payload canonicalization to Base64URL ---------- */
    public static String payloadJsonToBase64UrlJcs(String jsonPayloadPrettyOrCompact) {
        String canonical = JsonCanonicalizerJcs.canonicalize(jsonPayloadPrettyOrCompact);
        byte[] utf8 = canonical.getBytes(StandardCharsets.UTF_8);
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
     * Uses NONEwithECDSA (BC). Signature bytes are DER encoded (r,s).
     *
     * Requires an EC P-521 private key in PKCS#8 ("BEGIN PRIVATE KEY").
     */
    public static String signPreHashedES512NoHash(String pemEcPrivateKeyPkcs8, byte[] sha512Digest) throws Exception {
        PrivateKey jcaPriv = parseEcPrivateKeyFromPemPkcs8(pemEcPrivateKeyPkcs8);

        var s = java.security.Signature.getInstance("NONEwithECDSA", "BC");
        s.initSign(jcaPriv, new SecureRandom());
        s.update(sha512Digest);
        byte[] sigDer = s.sign();

        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigDer);
    }



    /**
     * Orchestrate detached signature creation and return Berlin Group wrapper JSON.
     *
     * @param protectedHeaderPrettyJson protected header in pretty JSON, may contain "sigT":"CURRENT"
     * @param payloadJson               business payload JSON; canonicalized via JCS
     * @param privateKeyPem             private key PEM:
     *                                 - for PS512: RSA PKCS#8 ("PRIVATE KEY") or PKCS#1 ("RSA PRIVATE KEY")
     *                                 - for ES512: EC P-521 PKCS#8 ("PRIVATE KEY")
     * @param pemCertificate            X.509 certificate PEM ("BEGIN CERTIFICATE") to embed as x5c[0]
     * @return pretty Berlin Group wrapper JSON with "protected" and "signature"
     */
    public static String signDetachedBerlinGroup(
            String protectedHeaderPrettyJson,
            String payloadJson,
            String privateKeyPem,
            String pemCertificate
    ) throws Exception {

        // 1) Resolve sigT first
        String headerWithSigT = resolveSigTCurrentUtc(protectedHeaderPrettyJson);

        // 2) Embed certificate into protected header as x5c[0] (base64 DER; NOT base64url)
        byte[] certDer = parseCertificateDerFromPem(pemCertificate);
        String certDerB64 = Base64.getEncoder().encodeToString(certDer);
        String headerWithX5c = injectX5cIntoProtectedHeaderJson(headerWithSigT, certDerB64);

        // 3) Compact + Base64URL encode the protected header
        String compactHeader = jsonMinify(headerWithX5c);
        String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(compactHeader.getBytes(StandardCharsets.UTF_8));

        // 4) Payload canonicalization via JCS
        String payloadB64 = payloadJsonToBase64UrlJcs(payloadJson);

        // 5 + 6) Compute signing input + SHA-512 digest
        SigningInput si = computeSigningInputAndHash(protectedB64, payloadB64);

        // 7) Read alg from protected header JSON and sign accordingly (registry-based)
        String alg = extractAlgFromProtectedHeaderJson(headerWithX5c);
        if (alg == null || alg.isEmpty()) {
            throw new IllegalArgumentException("Missing or empty 'alg' claim in protected header.");
        }

        DigestSigner signer = SIGNERS.get(alg);
        if (signer == null) {
            throw new IllegalArgumentException("Unsupported alg in protected header: " + alg);
        }

        String sigB64 = signer.sign(privateKeyPem, si.digestSha512);

        // 8) Berlin Group wrapper (detached)
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

    private static String resolveSigTCurrentUtc(String headerPretty) {
        String isoZ = java.time.Instant.now()
                .truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
                .toString();
        Matcher m = SIGT_CURRENT.matcher(headerPretty);
        return m.replaceAll("\"sigT\":\"" + isoZ + "\"");
    }

    
    /**
     * Produce a compact JSON representation of a JSON object by removing all
     * insignificant whitespace outside of string literals.
     *
     * Normative context:
     *   - RFC 7515 (JWS) requires the protected header to be a UTF-8 encoded JSON object
     *     which is Base64URL-encoded exactly as provided by the signer.
     *   - JSON itself (RFC 8259) defines whitespace (spaces, tabs, line breaks) as
     *     insignificant outside of string values.
     *
     * This method performs a minimal and deterministic "JSON compaction" by:
     *   - Removing all whitespace characters that are not part of a JSON string value
     *   - Preserving the original character content, string escaping, and member order
     *
     * Important:
     *   - This is NOT a JSON canonicalization algorithm.
     *   - No reordering of object members is performed.
     *   - No normalization of numbers or Unicode is performed.
     *
     * Rationale:
     *   - JWS does not mandate canonicalization of the protected header.
     *   - Any semantically equivalent JSON text may be used, as long as the exact
     *     UTF-8 byte sequence is consistently used for signing and verification.
     *   - Compacting the header avoids accidental differences caused by formatting
     *     (pretty-printing) while preserving full control over header semantics.
     *
     * Security note:
     *   - The resulting JSON text MUST be treated as an opaque byte sequence once
     *     Base64URL-encoded and included in the JWS signing input.
     *   - Any change to this representation (including whitespace) will invalidate
     *     the signature.
     */
    private static String jsonMinify(String s) {
        StringBuilder out = new StringBuilder(s.length());
        boolean inStr = false, esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                out.append(c);
                if (esc) { esc = false; }
                else if (c == '\\') { esc = true; }
                else if (c == '"') { inStr = false; }
            } else {
                if (c == '"') { inStr = true; out.append(c); }
                else if (!Character.isWhitespace(c)) { out.append(c); }
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
            throw new IllegalArgumentException("Protected header already contains x5c");
        }

        int end = headerJson.lastIndexOf('}');
        if (end < 0) throw new IllegalArgumentException("Invalid JSON: no closing '}'");

        int start = headerJson.indexOf('{');
        if (start < 0 || start > end) throw new IllegalArgumentException("Invalid JSON: no opening '{'");
        boolean emptyObject = headerJson.substring(start + 1, end).trim().isEmpty();

        String insertion = (emptyObject ? "" : ",") + "\"x5c\":[\"" + certDerBase64 + "\"]";
        return headerJson.substring(0, end) + insertion + headerJson.substring(end);
    }

    private static String extractAlgFromProtectedHeaderJson(String protectedHeaderJson) {
        Matcher m = ALG_PATTERN.matcher(protectedHeaderJson);
        return m.find() ? m.group(1) : null;
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
        while (tmp > 0) { bytes++; tmp >>= 8; }
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
        for (byte[] a : arrs) { System.arraycopy(a, 0, out, off, a.length); off += a.length; }
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        String h = hex.replaceAll("\\s+", "");
        if ((h.length() & 1) != 0) throw new IllegalArgumentException("Odd-length hex: " + hex);
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(h.charAt(2*i), 16);
            int lo = Character.digit(h.charAt(2*i+1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid hex at pos " + (2*i));
            out[i] = (byte)((hi << 4) | lo);
        }
        return out;
    }

    /* =========================== Demo =========================== */

    /**
     * Demo prints a Berlin Group wrapper. Switch alg in header to "PS512" or "ES512".
     *
     * IMPORTANT for ES512:
     *   - Provide an EC P-521 PKCS#8 private key (BEGIN PRIVATE KEY) matching the certificate.
     */
    public static void main(String[] args) throws Exception {

    	
        String payloadJson = """
                {
                  "amount": "10.50",
                  "currency": "EUR",
                  "debtor": {"iban":"DE02120300000000202051"},
                  "creditor": {"iban":"DE75512108001245126199"},
                  "remittanceInformation": "BG-Sample"
                }
                """;
    	
        String headerPretty = """
                {
                  "alg": "ES512",
                  "sigT": "CURRENT",
                  "sub": "myPaymentResourceId12345",
                  "canonAlg": "http://json-canonicalization.org/algorithm",
                  "x5u": "https://example.org/certs/meine_test_gmbh_cert.pem",
                  "crit": ["canonAlg", "sigT", "sub"]
                }
                """;


   /*
        // a) PS512: RSA private key (PKCS#8 or PKCS#1) - kept verbatim from your example . CHANGE protected header "alg" is ES512.
        String pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
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
Qz7SYrg06Cfx/JlNqM/DpP5K
-----END PRIVATE KEY-----

                """;



        // Certificate to embed into protected header as x5c[0]
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

       */
        
        
//   /*        
        // b) ES512: Set with an EC P-521 PKCS#8 private key. CHANGE protected header "alg" is ES512.

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



        // Certificate to embed into protected header as x5c[0]
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
 //   */        
        

        String bg = signDetachedBerlinGroup(headerPretty, payloadJson, pemPrivateKey, pemCertificate);
        System.out.println(bg);
    }
}
