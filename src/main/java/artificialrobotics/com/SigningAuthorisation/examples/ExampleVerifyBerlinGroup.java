package artificialrobotics.com.SigningAuthorisation.examples;

import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Example: Verification of a detached signature in Berlin Group wrapper.
 *
 * Step-by-step flow (demo-friendly):
 *   1) Parse wrapper -> get protected + signature
 *   2) Decode protected header JSON
 *   3) Extract and validate "sub"
 *   4) Extract and sanity-check "iat"
 *   5) Optionally inspect "x5t#S256" (informational consistency check)
 *   6) Extract "alg" and check it is PS512 or ES512
 *   7) Payload handling:
 *        - if "canonAlg":"JCS" is present in the protected header:
 *              canonicalize payload via JCS and Base64URL-encode it
 *        - if no "canonAlg" is present:
 *              use payload as given and Base64URL-encode it
 *   8) Build signing input: ASCII(protectedB64 + "." + payloadB64)
 *   9) Compute SHA-512 over signing input
 *  10) Decode signature bytes
 *  11) Single verification call: verifySignature(protected, signature, messageToVerify)
 *
 * Project note:
 *   - messageToVerify == SHA-512(signingInput)
 *   - For PS512: messageToVerify is the RSA-PSS pre-hash
 *   - For ES512: messageToVerify is the final ECDSA message for NONEwithECDSA
 *
 * Important ES512 update:
 *   - The signer emits a JWS-compliant JOSE ECDSA signature format (raw R||S),
 *     not DER.
 *   - Therefore, verification must transcode raw R||S -> DER before passing the
 *     signature to NONEwithECDSA.
 *
 * Certificate references:
 *   - x5c is used consistently in this example as the source for extracting the
 *     public key / leaf certificate.
 *   - x5t#S256 may be present and can be checked for consistency, but is not used
 *     as the key source here.
 *
 * Payload canonicalization:
 *   - This verifier no longer assumes JCS implicitly.
 *   - JCS is applied only if the protected header explicitly contains "canonAlg":"JCS".
 */
public class ExampleVerifyBerlinGroup {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Pattern SUB_PATTERN =
            Pattern.compile("\"sub\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern ALG_PATTERN =
            Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern IAT_PATTERN =
            Pattern.compile("\"iat\"\\s*:\\s*(\\d+)");
    private static final Pattern X5T_S256_PATTERN =
            Pattern.compile("\"x5t#S256\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern CANON_ALG_PATTERN =
            Pattern.compile("\"canonAlg\"\\s*:\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);

    /** Algorithm registry (selection via map, no switch needed inside verifySignature). */
    private static final Map<String, AlgoVerifier> VERIFIERS = new HashMap<>();
    static {
        VERIFIERS.put("PS512", ExampleVerifyBerlinGroup::verifyPs512OverDigest);
        VERIFIERS.put("ES512", ExampleVerifyBerlinGroup::verifyEs512NoHash);
    }

    @FunctionalInterface
    private interface AlgoVerifier {
        boolean verify(PublicKey pub, byte[] messageToVerify, byte[] signature) throws Exception;
    }

    /* ---------- Public API ---------- */

    public static boolean verifyDetachedBerlinGroup(String berlinGroupJson, String payloadJson) throws Exception {

        // 1) Extract protected and signature from the Berlin Group wrapper
        BG bg = parseBerlinGroupWrapper(berlinGroupJson);

        // 2) Decode protected header JSON
        byte[] protectedBytes = Base64.getUrlDecoder().decode(bg.protectedB64);
        String protectedJson = new String(protectedBytes, StandardCharsets.UTF_8);

        // 3) Extract and validate "sub" claim
        String sub = extractClaim(protectedJson, SUB_PATTERN);
        if (sub == null || sub.isEmpty()) {
            throw new IllegalArgumentException("Missing or empty 'sub' claim in protected header.");
        }

        // 4) Extract and sanity-check "iat"
        Long iat = extractNumericClaim(protectedJson, IAT_PATTERN);
        if (iat == null || iat <= 0L) {
            throw new IllegalArgumentException("Missing or invalid 'iat' claim in protected header.");
        }

        // 5) Optional informational check of x5t#S256 consistency against x5c[0]
        String x5tS256 = extractClaim(protectedJson, X5T_S256_PATTERN);
        if (x5tS256 != null && !x5tS256.isBlank()) {
            String expected = computeX5tS256FromProtectedHeaderX5c(protectedJson);
            if (!x5tS256.equals(expected)) {
                throw new IllegalArgumentException("x5t#S256 does not match x5c[0] certificate.");
            }
        }

        // 6) Extract alg and check it is PS512 or ES512
        String alg = extractClaim(protectedJson, ALG_PATTERN);
        if (alg == null || alg.isEmpty()) {
            throw new IllegalArgumentException("Missing or empty 'alg' claim in protected header.");
        }
        if (!"PS512".equals(alg) && !"ES512".equals(alg)) {
            throw new IllegalArgumentException("Unsupported alg in protected header: " + alg);
        }

        // 7) Payload handling depending on canonAlg in protected header
        String payloadB64 = payloadJsonToBase64Url(payloadJson, protectedJson);

        // 8) Build signing input (ASCII) as defined by RFC 7515 §5
        byte[] signingInput = (bg.protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

        // 9) Compute SHA-512 over signing input
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(signingInput);

        // 10) Decode signature bytes
        byte[] sig = Base64.getUrlDecoder().decode(bg.signatureB64);

        // 11) Single verification call
        return verifySignature(protectedJson, sig, digest);
    }

    /* ---------- Step 11: single verification method ---------- */

    public static boolean verifySignature(String protectedJson, byte[] signature, byte[] messageToVerify) throws Exception {

        String alg = extractClaim(protectedJson, ALG_PATTERN);
        if (alg == null || alg.isEmpty()) {
            throw new IllegalArgumentException("Missing or empty 'alg' claim in protected header.");
        }

        PublicKey pub = extractLeafPublicKeyFromProtectedHeader(protectedJson);

        AlgoVerifier verifier = VERIFIERS.get(alg);
        if (verifier == null) {
            throw new IllegalArgumentException("Unsupported alg: " + alg);
        }

        return verifier.verify(pub, messageToVerify, signature);
    }

    /* ---------- Payload handling ---------- */

    public static String payloadJsonToBase64Url(String jsonPayloadPrettyOrCompact, String protectedHeaderJson) {
        String canonAlg = extractClaim(protectedHeaderJson, CANON_ALG_PATTERN);

        String payloadToEncode;
        if (canonAlg == null || canonAlg.isBlank()) {
            payloadToEncode = jsonPayloadPrettyOrCompact;
        } else { // apply canonicalization on payload 
            payloadToEncode = JsonCanonicalizerJcs.canonicalize(jsonPayloadPrettyOrCompact);
        }

        byte[] utf8 = payloadToEncode.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(utf8);
    }

    /* ---------- Algorithm implementations ---------- */

    /** PS512 verification over messageToVerify (digest) using RAWRSASSA-PSS (pre-hash model). */
    private static boolean verifyPs512OverDigest(PublicKey pub, byte[] digest, byte[] signature) throws Exception {
        var s = java.security.Signature.getInstance("RAWRSASSA-PSS", "BC");
        var pss = new java.security.spec.PSSParameterSpec(
                "SHA-512", "MGF1",
                new java.security.spec.MGF1ParameterSpec("SHA-512"),
                64, 1
        );
        s.setParameter(pss);
        s.initVerify(pub);
        s.update(digest);
        return s.verify(signature);
    }

    /**
     * ES512 verification over messageToVerify (digest) WITHOUT internal hashing.
     *
     * Important:
     *   - The signer emits JOSE raw R||S encoding (132 bytes for ES512 / P-521).
     *   - JCA NONEwithECDSA expects DER.
     *   - Therefore raw R||S is transcoded to DER before verification.
     */
    private static boolean verifyEs512NoHash(PublicKey pub, byte[] digest, byte[] sigJoseConcat) throws Exception {
        byte[] sigDer = transcodeConcatToDer(sigJoseConcat, 66);

        var s = java.security.Signature.getInstance("NONEwithECDSA", "BC");
        s.initVerify(pub);
        s.update(digest);
        return s.verify(sigDer);
    }

    /* ---------- Protected header x5c extraction ---------- */

    public static PublicKey extractLeafPublicKeyFromProtectedHeader(String protectedHeaderJson) throws Exception {
        String leafCertDerB64 = extractFirstStringFromJsonArray(protectedHeaderJson, "\"x5c\"");
        if (leafCertDerB64 == null) {
            throw new IllegalArgumentException("Missing x5c[0] in protected header.");
        }

        byte[] certDer = Base64.getDecoder().decode(leafCertDerB64);
        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        var cert = (java.security.cert.X509Certificate)
                cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));
        return cert.getPublicKey();
    }

    private static String computeX5tS256FromProtectedHeaderX5c(String protectedHeaderJson) throws Exception {
        String leafCertDerB64 = extractFirstStringFromJsonArray(protectedHeaderJson, "\"x5c\"");
        if (leafCertDerB64 == null) {
            throw new IllegalArgumentException("Missing x5c[0] in protected header.");
        }
        byte[] certDer = Base64.getDecoder().decode(leafCertDerB64);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certDer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String extractFirstStringFromJsonArray(String json, String keyWithQuotes) {
        int k = json.indexOf(keyWithQuotes);
        if (k < 0) return null;

        int colon = json.indexOf(':', k);
        if (colon < 0) return null;

        int arrStart = json.indexOf('[', colon);
        if (arrStart < 0) return null;

        int q1 = json.indexOf('"', arrStart);
        if (q1 < 0) return null;

        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;

        return json.substring(q1 + 1, q2);
    }

    /* ---------- Minimal BG wrapper parsing ---------- */

    public static final class BG {
        public final String protectedB64;
        public final String signatureB64;

        public BG(String p, String s) {
            this.protectedB64 = p;
            this.signatureB64 = s;
        }
    }

    public static BG parseBerlinGroupWrapper(String json) {
        String obj = json.replaceAll("[\\r\\n]", "").trim();
        String prot = extractJsonString(obj, "\"protected\"");
        String sig = extractJsonString(obj, "\"signature\"");
        if (prot == null || sig == null) {
            throw new IllegalArgumentException("Missing 'protected' or 'signature' in Berlin Group JSON.");
        }
        return new BG(prot, sig);
    }

    private static String extractJsonString(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) return null;
        int colon = json.indexOf(':', i);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    private static String extractClaim(String json, Pattern p) {
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static Long extractNumericClaim(String json, Pattern p) {
        Matcher m = p.matcher(json);
        if (!m.find()) {
            return null;
        }
        return Long.parseLong(m.group(1));
    }

    /* ---------- JOSE raw R||S -> DER for ECDSA verification ---------- */

    /**
     * Converts JOSE raw ECDSA signature R||S into ASN.1 DER SEQUENCE.
     *
     * For ES512 / P-521:
     *   - fieldSizeBytes = 66
     *   - raw signature length = 132
     */
    private static byte[] transcodeConcatToDer(byte[] jwsSignature, int fieldSizeBytes) {
        if (jwsSignature == null || jwsSignature.length != fieldSizeBytes * 2) {
            throw new IllegalArgumentException("Invalid JWS ECDSA signature length.");
        }

        byte[] r = new byte[fieldSizeBytes];
        byte[] s = new byte[fieldSizeBytes];
        System.arraycopy(jwsSignature, 0, r, 0, fieldSizeBytes);
        System.arraycopy(jwsSignature, fieldSizeBytes, s, 0, fieldSizeBytes);

        byte[] rDer = unsignedIntegerToDer(r);
        byte[] sDer = unsignedIntegerToDer(s);

        int seqLen = rDer.length + sDer.length;
        byte[] seqLenEnc = derLength(seqLen);

        byte[] out = new byte[1 + seqLenEnc.length + seqLen];
        int pos = 0;
        out[pos++] = 0x30; // SEQUENCE
        System.arraycopy(seqLenEnc, 0, out, pos, seqLenEnc.length);
        pos += seqLenEnc.length;
        System.arraycopy(rDer, 0, out, pos, rDer.length);
        pos += rDer.length;
        System.arraycopy(sDer, 0, out, pos, sDer.length);

        return out;
    }

    private static byte[] unsignedIntegerToDer(byte[] value) {
        int firstNonZero = 0;
        while (firstNonZero < value.length - 1 && value[firstNonZero] == 0) {
            firstNonZero++;
        }

        int len = value.length - firstNonZero;
        boolean needsLeadingZero = (value[firstNonZero] & 0x80) != 0;

        int contentLen = len + (needsLeadingZero ? 1 : 0);
        byte[] lenEnc = derLength(contentLen);

        byte[] out = new byte[1 + lenEnc.length + contentLen];
        int pos = 0;
        out[pos++] = 0x02; // INTEGER
        System.arraycopy(lenEnc, 0, out, pos, lenEnc.length);
        pos += lenEnc.length;

        if (needsLeadingZero) {
            out[pos++] = 0x00;
        }

        System.arraycopy(value, firstNonZero, out, pos, len);
        return out;
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        }

        int temp = length;
        int numBytes = 0;
        while (temp > 0) {
            numBytes++;
            temp >>= 8;
        }

        byte[] out = new byte[1 + numBytes];
        out[0] = (byte) (0x80 | numBytes);

        for (int i = numBytes; i > 0; i--) {
            out[i] = (byte) (length & 0xFF);
            length >>= 8;
        }

        return out;
    }

    /* ---------- Demo ---------- */

    public static void main(String[] args) throws Exception {

        // please insert here the Berlin Group signatureData
        // you can create e.g. with ExampleSignBerlinGroup
        String berlinGroupWrapper = """
{
  "signatureData": {
    "protected": "eyJhbGciOiJQUzUxMiIsIng1YyI6WyJNSUlGSmpDQ0ExcWdBd0lCQWdJVUduQWs3L3Z3OUJzZVVOR0pCZVhneWk0WGhGQXdRUVlKS29aSWh2Y05BUUVLTURTZ0R6QU5CZ2xnaGtnQlpRTUVBZ01GQUtFY01Cb0dDU3FHU0liM0RRRUJDREFOQmdsZ2hrZ0JaUU1FQWdNRkFLSURBZ0ZBTUdneEN6QUpCZ05WQkFZVEFrUkZNUlF3RWdZRFZRUUtEQXROZFhOMFpYSWdSMjFpU0RFVU1CSUdBMVVFQXd3TFRYVnpkR1Z5SUVkdFlrZ3hFekFSQmdOVkJBc01DbEJoZVcxbGJuUklkV0l4R0RBV0JnTlZCR0VNRDA1VVVrUkZMVWhTUWpFeU16UTFOakFlRncweU5qQXlNREV4TnpRME5UVmFGdzB6TmpBeE16QXhOelEwTlRWYU1HZ3hDekFKQmdOVkJBWVRBa1JGTVJRd0VnWURWUVFLREF0TmRYTjBaWElnUjIxaVNERVVNQklHQTFVRUF3d0xUWFZ6ZEdWeUlFZHRZa2d4RXpBUkJnTlZCQXNNQ2xCaGVXMWxiblJJZFdJeEdEQVdCZ05WQkdFTUQwNVVVa1JGTFVoU1FqRXlNelExTmpDQ0FhSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnR1BBRENDQVlvQ2dnR0JBTkcxOFh1SW40NSsrTXdwRHhjUzNwVTRLWGZDQ3pZajAxa3NaZzRDd2htNVdNQXBrdUJhOFM5UWtYREpmcHVkVStMcWhLK2FzZWd2dEZtR2RkUTJ1WE9BWlJBY1g5bVJ0S3VZSnVKYThHRXZiaWg0NXBMcnRDUEttRVNxbzlBOTF5VllpVXk0NmFQN2kwWGthRTY4eXROb2ZJU2x4NE1nRkt3WFBXK3MySDdXZk8vYVFETGFjUFdRYXNndGtpc0xjNWh6QndMM2RYNnZFbk1lQTBHQVFkNkdZOC9pdEFvZjNVK1NxMnVNUmQ5UkZiSTJ0T2RYWE1zdWw3aHAzNEFIN0ZqdWtTQ2cwZVF4T2pqNjJUM2tKNmNKT2ZCMWFjeGl2cUhUZm5Ib3l5YXlLcmtLOTV1LzFaVnFnanljVjYvMTc1U1NUb2ZYbWEvVmdTTnowMkNFb0orRGxSNG5LajhraStXUWk3QW84TzN3YlV0Rmw0bkhSZVExRjNoV05rbWpNOVBPekdidm9zZ2JTYlBZbzFjUS9OYnZsbjlReEZwdzViVWNJbkF4V212bkxSdEUyeWZnMi9JYis0OCtDamd1NUZ0RW9rb0hpTG50aEZwUUVNN1llL0x3emE0NklEYTRLcXBqR0ZMRGRUY0p3anQ3dzd2dCtUSW1sditTWW1BdG13SURBUUFCbzJBd1hqQU1CZ05WSFJNQkFmOEVBakFBTUE0R0ExVWREd0VCL3dRRUF3SUd3REFkQmdOVkhRNEVGZ1FVblltWWtVLzhZNzBTZkFOVGhWZTJBaUNTeTVrd0h3WURWUjBqQkJnd0ZvQVVuWW1Za1UvOFk3MFNmQU5UaFZlMkFpQ1N5NWt3UVFZSktvWklodmNOQVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdNRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTkJnbGdoa2dCWlFNRUFnTUZBS0lEQWdGQUE0SUJnUUFpbDhNQmxtOWlvUUVmWC9tbDRJc0dlNEdXaDRvSy9hcEVtN0R2dWdHMWZJdHh4L1JDSHM0ZW9iQ0NZdkE1WlBlRTAraWVBT2MzU3ZWUkRnRjEwQ29zS3RPRlFjM256QTBBTHZqSnliTXZVVHFKL243YU5hNmhTWE9GaVY4SHI0UjFPYmROcE9ReGRWTkRiSlN5c0xtNjNYWTg2VnVuV3BveG53VHVvSmJwR1h2NDNXQmwrcjI1Ull0VTUreCsxUFoya3p4UUVZclNLVTc4T212ZG0ydVR3QTdDdEU4bTB1a0RFRlR6WUlYRk5BbUtYdUM1WnQ1TlV0WXhkc1FJdGFKelE4OG9NTXJ5WVRYMUtMRTJlc0NndTUvdFFFa3VrKyt0QXp3RGYrd0ZzUDhmdHZOODEza1NqckFueEcrOW5IVzFlRGVaSTJWQXFkSFo0bi85bGVVdWcxbnpDaHY0dWZ0UW1zMHJ1clNidjBGNUFqZ2ZhaWVHT3lldCs4a2FSYVc4TldhNk1BWHhmSSt0SzZDaFZhMlNsT0ZBblRRMjdoMDhqZ0pUc01EK3hNS1B6cXdVY01JZXN3SGhZVWt4c3RPc2Y5NTlGZkcwS0VudDNnb1VtM2U3c0NNNngrOW9oMVU4TUlLcWZjUkZWb0FZT2lVVVNCeTdsdVhkZ0tNV3BYcz0iXSwieDV0I1MyNTYiOiJ6MXNVd1dpcUtDbXNubUZXcTlKTEhKRnlBR0FWeWMzWUlfNWNNejJWUXdvIiwic3ViIjoiYVBheW1lbnRSZXNJRCIsImlhdCI6MTc3NDMzOTcxMiwiY2Fub25BbGciOiJodHRwOi8vanNvbi1jYW5vbmljYWxpemF0aW9uLm9yZy9hbGdvcml0aG0ifQ",
    "signature": "lmpH87MZrTEQmb7G7_kDh12EtqRJMjXtEc5_yKrCCkHd97tIGV0Y5YMwGN-kSM9WMd6QzHHUos2l3_CQXLvbmpdq737xVMXQ7C3Fbmf8OEckOl5Vgx-0EC4Lal0ljpYuIvX1_O1qriDf_PbmrIKjr-XBovVr_Ym7MIxMUut3xGPjcqY9-4Nj_H892_PtXMjhyLhMkiabEf-aaKXi-YmaPZneie1PgDeXMwSfq5tZm5s8uPg0PGWaq2NsoOFc-U9HaYguZGco5vCAYwKQ810wCh7xyp-XDsjPzVLEiJkZ1T-kIDcw3tBLoB6CJS6L-29rfRuIDkMEoT-7grPBknkOpxzkZt5LPll9peadlFp1nWmLlKUaPJ5PJiapNqDtym5JmufKUdvbMaTB1hLbcPZiFGIagpiVCbx-NOPkQPgEVyBZ6hZrlplAV0dkBOf2aJZEc1mATBeSzSmpHd4Ly3fTTweEGkcOOYpOzdEl6_fyU7nZja4azB0JItz1IjJ-8xNv"
  }
}
                """;

        String payloadJson = """
{
 "amount": "10.50",
 "currency": "EUR",
 "debtor": {"iban":"DE02120300000000202051"},
 "creditor": {"iban":"DE75512108001245126199"},
 "remittanceInformation": "BG-Sample with .:_-äüöß@€"
}
                """;

        boolean ok = verifyDetachedBerlinGroup(berlinGroupWrapper, payloadJson);
        System.out.println("VALID (crypto-only, BG detached): " + ok);
    }
}