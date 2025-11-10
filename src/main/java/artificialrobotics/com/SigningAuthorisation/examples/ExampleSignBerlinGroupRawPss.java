package artificialrobotics.com.SigningAuthorisation.examples;

import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Example: Detached JWS signature in the Berlin Group wrapper using PS512,
 * with a strict "pre-hash" model (separating hashing and signing to enable private key processing via HSM).
 * Hint: In e.g. java.security hashing and encryption will be done in one functional step
 *
 * Flow:
 *   a) Protected header (pretty JSON) → compact JSON → Base64URL (RFC 7515). "sigT":"CURRENT" is resolved to UTC now.
 *   b) Payload canonicalization via JCS (RFC 8785) → Base64URL.
 *   c) JWS signing input = ASCII(protectedB64 + "." + payloadB64); compute SHA-512 (RFC 7518 PS512).
 *   d) Sign the precomputed SHA-512 digest using RAWRSASSA-PSS (BC provider) with PS512 params (RFC 8017 + RFC 7518).
 *   e) Return Berlin Group JSON wrapper { "signatureData": { "protected": "...", "signature": "..." } }.
 *
 * Specifications referenced:
 *   - RFC 7515 (JWS): structure, signing input, Base64URL handling
 *   - RFC 7518 (JWA): PS512 algorithm (RSA-PSS + SHA-512 + MGF1(SHA-512), saltLen=64)
 *   - RFC 8785 (JCS): JSON Canonicalization Scheme for payload stability
 *   - RFC 8017 (PKCS #1 v2.2): RSASSA-PSS encoding/verification
 *   - JCA/JCE: Java cryptographic provider and Signature API usage
 *   - ETSI TS 119 182 (JAdES) [context]: custom protected claims like sigT, etsiCanonicalization, crit
 */
public class ExampleSignBerlinGroupRawPss {

    /** Register Bouncy Castle provider so that "RAWRSASSA-PSS" is available via "BC". */
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Regex used to detect and replace "sigT":"CURRENT" in the protected header (case-insensitive). */
    private static final Pattern SIGT_CURRENT =
            Pattern.compile("\"sigT\"\\s*:\\s*\"CURRENT\"", Pattern.CASE_INSENSITIVE);

    /**
     * a) Convert a pretty protected header JSON to Base64URL of compact JSON.
     *    Also resolves "sigT":"CURRENT" to the current UTC timestamp (ISO-8601, seconds, 'Z'),
     *    matching the behavior in SignCmd.
     *
     * Rationale:
     *   - RFC 7515 requires the protected header to be UTF-8 JSON which is Base64URL-encoded.
     *   - Compacting removes irrelevant whitespace; key order is preserved as provided.
     *
     * @param prettyJsonProtectedHeaderUtcNow protected header, pretty JSON, containing "sigT":"CURRENT"
     * @return Base64URL encoded compact JSON of the protected header
     */
    public static String protectedHeaderToBase64Url(String prettyJsonProtectedHeaderUtcNow) {
        String withSigT = resolveSigTCurrentUtc(prettyJsonProtectedHeaderUtcNow);
        String compact = jsonMinify(withSigT);
        byte[] utf8 = compact.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
    }

    /**
     * b) Canonicalize the JSON payload using JCS (RFC 8785) and return Base64URL of its UTF-8 bytes.
     *
     * Why JCS:
     *   - Ensures a stable byte representation (field order, whitespace, number formatting),
     *     so the same logical JSON yields the same signature.
     *
     * @param jsonPayloadPrettyOrCompact payload JSON (object/array), pretty or compact
     * @return Base64URL encoded canonical JSON bytes
     */
    public static String payloadJsonToBase64UrlJcs(String jsonPayloadPrettyOrCompact) {
        String canonical = JsonCanonicalizerJcs.canonicalize(jsonPayloadPrettyOrCompact);
        byte[] utf8 = canonical.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
    }

    /**
     * c) Build the JWS signing input and compute SHA-512 over it.
     *    Signing input per RFC 7515 §5: ASCII(protectedB64 + "." + payloadB64)
     *    Digest per RFC 7518 (PS512 uses SHA-512).
     *
     * @param protectedB64 Base64URL(protected header)
     * @param payloadB64   Base64URL(canonical payload)
     * @return container with raw signing input bytes, SHA-512 digest, and digest as Base64 (useful for logs/JAdES artifacts)
     * @throws Exception if SHA-512 is unavailable (unlikely on standard JREs)
     */
    public static SigningInput computeSigningInputAndHash(String protectedB64, String payloadB64) throws Exception {
        byte[] signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] digest = md.digest(signingInput);
        String digestB64 = Base64.getEncoder().encodeToString(digest);
        return new SigningInput(signingInput, digest, digestB64);
    }

    /**
     * d) Sign ONLY the precomputed SHA-512 digest using RSASSA-PSS with PS512 parameters.
     *    Uses JCA/JCE Signature with Bouncy Castle provider and algorithm "RAWRSASSA-PSS".
     *
     * Details:
     *   - Pre-hash model: we pass SHA-512(signingInput) directly → no re-hashing by the Signature object.
     *   - RSASSA-PSS parameters per RFC 7518 (PS512) and RFC 8017:
     *       * Hash: SHA-512
     *       * MGF:  MGF1(SHA-512)
     *       * saltLen: 64 (== SHA-512 output size)
     *       * trailerField: 0xBC
     *
     * @param pemPrivateKeyPkcs8OrPkcs1 RSA private key in PEM (PKCS#8 or PKCS#1; PKCS#1 is wrapped to PKCS#8)
     * @param sha512Digest              precomputed SHA-512 digest of the JWS signing input
     * @return Base64URL(signature bytes)
     * @throws Exception on key parsing or signing failures
     */
    public static String signPreHashedPS512(String pemPrivateKeyPkcs8OrPkcs1, byte[] sha512Digest) throws Exception {
        PrivateKey jcaPriv = parsePrivateKeyFromPem(pemPrivateKeyPkcs8OrPkcs1);

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

    /**
     * e) Orchestrate the detached JWS creation and return the Berlin Group wrapper JSON (pretty).
     *    The payload is not embedded (detached); the verifier must receive it separately.
     *
     * Expected header claims (example): alg="PS512", sigT (resolved), sub, etsiCanonicalization, x5u, crit[…].
     *
     * @param protectedHeaderPrettyJson protected header in pretty JSON, with "sigT":"CURRENT"
     * @param payloadJson               business payload JSON; will be canonicalized via JCS
     * @param rsaPrivateKeyPem          RSA private key (PEM, PKCS#8 or PKCS#1)
     * @return pretty Berlin Group JSON wrapper with "protected" and "signature"
     * @throws Exception on processing errors
     */
    public static String signDetachedBerlinGroup(
            String protectedHeaderPrettyJson,
            String payloadJson,
            String rsaPrivateKeyPem
    ) throws Exception {
        String protectedB64 = protectedHeaderToBase64Url(protectedHeaderPrettyJson); // step (a)
        String payloadB64   = payloadJsonToBase64UrlJcs(payloadJson);               // step (b)
        SigningInput si     = computeSigningInputAndHash(protectedB64, payloadB64); // step (c)
        String sigB64       = signPreHashedPS512(rsaPrivateKeyPem, si.digestSha512);// step (d)

        // step (e): Berlin Group wrapper (detached)
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

    /**
     * Simple holder for the JWS signing input and its SHA-512 digest.
     * Useful to expose both raw bytes (for signing) and a Base64 form (for logs/JAdES artifacts).
     */
    public static final class SigningInput {
        public final byte[] signingInput;  // ASCII("protectedB64.payloadB64") per RFC 7515
        public final byte[] digestSha512;  // SHA-512(signingInput) per RFC 7518 (PS512)
        public final String digestBase64;  // Base64(digestSha512), informational
        public SigningInput(byte[] signingInput, byte[] digestSha512, String digestBase64) {
            this.signingInput = signingInput;
            this.digestSha512 = digestSha512;
            this.digestBase64 = digestBase64;
        }
    }

    /**
     * Replace "sigT":"CURRENT" with the current UTC timestamp (ISO-8601, seconds precision, trailing 'Z').
     * Mirrors SignCmd behavior for consistency across tools.
     */
    private static String resolveSigTCurrentUtc(String headerPretty) {
        String isoZ = java.time.Instant.now()
                .truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
                .toString();
        Matcher m = SIGT_CURRENT.matcher(headerPretty);
        return m.replaceAll("\"sigT\":\"" + isoZ + "\"");
    }

    /**
     * Minimal JSON "minifier": removes whitespace outside string literals.
     * Keeps content and key order intact while producing a compact representation for JWS header encoding.
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

    /**
     * Parse a PEM private key (PKCS#8 or PKCS#1). If PKCS#1 is provided, it is wrapped
     * into a minimal PKCS#8 (PrivateKeyInfo) so that JCA can consume it.
     * Note: encrypted PKCS#8 is not handled in this concise example.
     */
    private static PrivateKey parsePrivateKeyFromPem(String pem) throws Exception {
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
            throw new IllegalArgumentException("Unsupported PEM type: " + type);
        }
    }

    /**
     * Read a single PEM object from a string.
     */
    private static PemObject readPem(String pem) throws IOException {
        try (Reader r = new StringReader(pem); PemReader pr = new PemReader(r)) {
            PemObject po = pr.readPemObject();
            if (po == null) throw new IllegalArgumentException("No PEM object found");
            return po;
        }
    }

    /**
     * Wrap a PKCS#1 RSAPrivateKey into a minimal PKCS#8 PrivateKeyInfo.
     *
     * Structure (ASN.1):
     *   PrivateKeyInfo ::= SEQUENCE {
     *     version              INTEGER (0),
     *     privateKeyAlgorithm  AlgorithmIdentifier { rsaEncryption (1.2.840.113549.1.1.1), NULL },
     *     privateKey           OCTET STRING (RSAPrivateKey)
     *   }
     *
     * Here, AlgorithmIdentifier is provided as a readable HEX string and converted to bytes:
     *   "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"
     * which encodes SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }.
     *
     * This keeps the example self-contained without external ASN.1 libraries.
     */
    private static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1Der) {
        String algIdHex = "300D06092A864886F70D0101010500";  // DER: SEQ(OID rsaEncryption, NULL)
        byte[] algId = hexToBytes(algIdHex);

        byte[] version = new byte[] { 0x02, 0x01, 0x00 };        // INTEGER 0
        byte[] pkcs1Octet = derOctetString(pkcs1Der);            // OCTET STRING (RSAPrivateKey)
        byte[] body = concat(version, algId, pkcs1Octet);
        return derSequence(body);                                 // SEQUENCE (PrivateKeyInfo)
    }

    /* ---- Minimal DER helpers for the PKCS#1→PKCS#8 wrapper above ---- */

    /**
     * Build a DER OCTET STRING around the provided value.
     */
    private static byte[] derOctetString(byte[] val) {
        byte[] len = derLen(val.length);
        byte[] out = new byte[1 + len.length + val.length];
        out[0] = 0x04;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(val, 0, out, 1 + len.length, val.length);
        return out;
    }

    /**
     * Build a DER SEQUENCE for the provided body.
     */
    private static byte[] derSequence(byte[] body) {
        byte[] len = derLen(body.length);
        byte[] out = new byte[1 + len.length + body.length];
        out[0] = 0x30;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(body, 0, out, 1 + len.length, body.length);
        return out;
    }

    /**
     * Encode a DER length field for the given length (short/long form).
     */
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

    /**
     * Concatenate any number of byte arrays.
     */
    private static byte[] concat(byte[]... arrs) {
        int n = 0, off = 0;
        for (byte[] a : arrs) n += a.length;
        byte[] out = new byte[n];
        for (byte[] a : arrs) { System.arraycopy(a, 0, out, off, a.length); off += a.length; }
        return out;
    }

    /**
     * Convert a hex string (spaces allowed) to a byte array.
     * Throws if length is odd or characters are not hex digits.
     */
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
     * Minimal end-to-end demo building a detached PS512 JWS inside the Berlin Group wrapper.
     * Prints the resulting JSON to stdout.
     */
    public static void main(String[] args) throws Exception {
        String headerPretty = """
                {
                  "alg": "PS512",
                  "sigT": "CURRENT",
                  "sub": "myPaymentResourceId12345",
                  "etsiCanonicalization": "http://json-canonicalization.org/algorithm",
                  "x5u": "https://example.org/certs/meine_test_gmbh_cert.pem",
                  "crit": ["etsiCanonicalization", "sigT", "sub"]
                }
                """;

        String payloadJson = """
                {
                  "amount": "10.50",
                  "currency": "EUR",
                  "debtor": {"iban":"DE02120300000000202051"},
                  "creditor": {"iban":"DE75512108001245126199"},
                  "remittanceInformation": "BG-Sample"
                }
                """;

        // Provided PKCS#8 PEM private key (kept verbatim for this example).
        String pem = """
                -----BEGIN PRIVATE KEY-----
                MIIG/gIBADANBgkqhkiG9w0BAQEFAASCBugwggbkAgEAAoIBgQCvSAmqXAv5CF8r
                ocLeVCvjcl2MdAEYxYko9CcNwqMZRlA7URP2sf17uTh7UIwpl2tRFixfpjj/G2v7
                RgDAKF56ul4R6t+t7FxzVU34bPc2daDwcAyFgVvypj1Gg3ZioPBcW2tgEUaTvGTj
                b8Mzt+IviSrSYZ74Mp6wi+vz7bHM/HgIsazsM55fgAEwOP5G6TYcW/4I8Dfn3d+B
                Kf3hqPTDWLmtbXDGixAY68F0/U45hQ2ojKrHpnH5XXg1LQz5QOc+Xmn6skHd3R81
                /EHN6wI0Fdh2H4CflV+AbdX0QMkadr3SKTT5RQJ4DE49L5pUmXh7Dfpeo4y1oPAn
                G03hZls5HgCcpxVhBc/Fbwvo3VcwSejQUcVXoGwMverupz3zAI05NwAIQ37q2OXE
                7rxzU4aM7aP55JdXKqyj0t/ftbkAcrTKb8wWmgm4GuFyIs63kEiNwaAGZBc2WkhC
                vmNBRGLzdhKnKbK7LHwvowV9dpLjR+H71C1E5Z9zQMpTgJz9GuECAwEAAQKCAYAV
                dIXqWnYEt6eemaBWworUvm0BAjoYJCXT437cSlTYhSjQ+e2tpr/WYyeswIFHngc+
                1636z0fuwhaHnVv+KXLXJvTY0J0sluACJhDzNbNU8TUP+UcvGFR+8SZS+UiGbhi9
                1VrhWXwAHXFj/YwxSnLfSrT5J4Xj755JEfeB1jiLVOQEfGskRnU+T1bV5kQJvgYn
                loMT6QOO2DPBhbhT5PCA8N1Zgynow6DmzATUIyVuGQFA/mbxJUiSM4TBTZBm+jCf
                8v05OVml6EQwcdIh57eB3FCGSwKHVUGdl1BLw5bRrNh58+AcQ15qIdhe424rliAM
                cHpnJC4OuhgJIJCH0MVUm6uSs55U7GaA1PNQu+hLyOIMvuurqR3j9X1qn8suK3J8
                pkDFvq6KeoDugsoWulTqzvr0pn0eG6YEyIKnwJEC204zUvu4iwKNKQ9w56eJ4+i3
                FcMtHZkUFeV7HXw6ZZhMzUk4wdA6tJDJLjN9oSlvqTHXzmu1stbgWmW8pGtFDdkC
                gcEA6SD5n9JXXN0sQ9KQyAzuRhAnjRVCiI8jYmenVzA23y2SXtQiQE5v87Ho27Yy
                +FvFvgdq99eUj8Le6+1OWa8BS9psHoBwYo7acwoRjloVuov2XGm3zb+hQCVKDRYB
                En3mgNx5ibIk90bqk2Z0SlxerNg6hD7IpDK6CoyL1tQ0jXJbNaofjlcHZ+yFsYmP
                uBpiWoQgFLCgTr6xmiN7F+CioyYqzO28YLoMxGQj+3cRsyAx1LVbQ7uVDh/uLdGY
                NmDvAoHBAMB6OefokX4RDQcIe/5XTJ6RAfKxPredFexWy8diT9BTodHIBN5A16ej
                xzNFi2OB8C7vfh4Eq8jvJd8P0fKEUaZCXJIXCdHDoTnGj5XUmVsnQ0Qy14ZHX1ko
                UTl6lhrTbp2GEnYpDZSQ6j9kI1lEZQvvMEjcUiiSlx/dGX/Pju9SRE64C8YFQX53
                Wrt1K80e4xrYEwgUJwGuTYwbyhqm31HbbNx/tmJ2qfQ+y69rlty3X3JcbSh2a4/J
                SjYU4qWhLwKBwGk2KZI4cpcFdjmxqQev1kUme0MPyjQpLVX2463Uo577SSik4kRV
                Ye8AZs/pnX06pbaKUHtD/tcWolalhYuyEIq0K8FkQ9QnFm1+qMeu3kmPawLv7zTa
                /CIf8hiPyrIWwdV8Kxm6nTY/+hPF1EvO/idReq8+SnzYK+Ag5+dvY7xGVOWWPqGV
                o1ECjJ/ALm1u8t5Y7MWJpP+EzlB7HM184slwqzZLQI4CyUpEy3xskz9dE0AlDOg3
                myCBxpNFGUXJXwKBwQCpiX+D1AiDYIV3EnQVHdQxP0zV9mVl2gm7eOBZqTDgMSox
                29rd4YOS9+G4OaODbKqgzPbrffXKMUvMZOTqlr5Mkdt0GrLdf1F90HYc5XyHG9hW
                M+o/LpK/t5GD7YRV8LJYMgYE6jg6CkMqvwubz3CpyG9hXh9H+Yb/3AJf3/TovC/K
                nrZQH8UGnh7fS1/fdztXI8fvr8CD7IIFzVyBiUbflUUYG64MoLUmnEFRLJVfqG18
                EAleQKCRsB2b8V2JwqUCgcEA2Q9cx3F9whx+hKnSl2Ie5VLD2IGy0jfTEIdD66sl
                GmDgyu0gtBfTQayjyhcVayZUIUWaTm13ao27MXnKg3NyV5v0PIzzrGeO0lWMwP/f
                ej2pJFvX+DkDZlSpLF80iJBrgsOEkYoSUlb2xwDQwZxYon/Y11WwPw2oIdmxarhC
                kuxQhqrH2fKIoWOLWgNH+dqnucap2iHEX/qlHMqDViiaZIEgSuC/ZvqJIOUSCR4D
                topoK0zse8la2AVXohuXHPqq
                -----END PRIVATE KEY-----
                """;

        String bg = signDetachedBerlinGroup(headerPretty, payloadJson, pem);
        System.out.println(bg);
    }
}
