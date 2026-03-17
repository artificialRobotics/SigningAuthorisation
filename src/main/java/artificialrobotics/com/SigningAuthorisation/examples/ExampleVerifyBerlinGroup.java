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
 *   7) Canonicalize payload using JCS and Base64URL-encode it (mirrors signer)
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
 *   - The signer now emits a JWS-compliant JOSE ECDSA signature format (raw R||S),
 *     not DER.
 *   - Therefore, verification must transcode raw R||S -> DER before passing the
 *     signature to NONEwithECDSA.
 *
 * Certificate references:
 *   - x5c is used consistently in this example as the source for extracting the
 *     public key / leaf certificate.
 *   - x5t#S256 may be present and can be checked for consistency, but is not used
 *     as the key source here.
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

        // 7) Canonicalize payload using JCS and Base64URL-encode it (mirrors signer)
        String payloadB64 = payloadJsonToBase64UrlJcs(payloadJson);

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

    /* ---------- Payload canonicalization ---------- */

    public static String payloadJsonToBase64UrlJcs(String jsonPayloadPrettyOrCompact) {
        String canonical = JsonCanonicalizerJcs.canonicalize(jsonPayloadPrettyOrCompact);
        byte[] utf8 = canonical.getBytes(StandardCharsets.UTF_8);
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
    "protected": "eyJhbGciOiJQUzUxMiIsInN1YiI6ImFQYXltZW50UmVzSUQiLCwiaWF0IjoxNzczNzQ4NzUwLCJ4NWMiOlsiTUlJRkpqQ0NBMXFnQXdJQkFnSVVHbkFrNy92dzlCc2VVTkdKQmVYZ3lpNFhoRkF3UVFZSktvWklodmNOQVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdNRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTkJnbGdoa2dCWlFNRUFnTUZBS0lEQWdGQU1HZ3hDekFKQmdOVkJBWVRBa1JGTVJRd0VnWURWUVFLREF0TmRYTjBaWElnUjIxaVNERVVNQklHQTFVRUF3d0xUWFZ6ZEdWeUlFZHRZa2d4RXpBUkJnTlZCQXNNQ2xCaGVXMWxiblJJZFdJeEdEQVdCZ05WQkdFTUQwNVVVa1JGTFVoU1FqRXlNelExTmpBZUZ3MHlOakF5TURFeE56UTBOVFZhRncwek5qQXhNekF4TnpRME5UVmFNR2d4Q3pBSkJnTlZCQVlUQWtSRk1SUXdFZ1lEVlFRS0RBdE5kWE4wWlhJZ1IyMWlTREVVTUJJR0ExVUVBd3dMVFhWemRHVnlJRWR0WWtneEV6QVJCZ05WQkFzTUNsQmhlVzFsYm5SSWRXSXhHREFXQmdOVkJHRU1EMDVVVWtSRkxVaFNRakV5TXpRMU5qQ0NBYUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0dQQURDQ0FZb0NnZ0dCQU5HMThYdUluNDUrK013cER4Y1MzcFU0S1hmQ0N6WWowMWtzWmc0Q3dobTVXTUFwa3VCYThTOVFrWERKZnB1ZFUrTHFoSythc2VndnRGbUdkZFEydVhPQVpSQWNYOW1SdEt1WUp1SmE4R0V2YmloNDVwTHJ0Q1BLbUVTcW85QTkxeVZZaVV5NDZhUDdpMFhrYUU2OHl0Tm9mSVNseDRNZ0ZLd1hQVytzMkg3V2ZPL2FRRExhY1BXUWFzZ3RraXNMYzVoekJ3TDNkWDZ2RW5NZUEwR0FRZDZHWTgvaXRBb2YzVStTcTJ1TVJkOVJGYkkydE9kWFhNc3VsN2hwMzRBSDdGanVrU0NnMGVReE9qajYyVDNrSjZjSk9mQjFhY3hpdnFIVGZuSG95eWF5S3JrSzk1dS8xWlZxZ2p5Y1Y2LzE3NVNTVG9mWG1hL1ZnU056MDJDRW9KK0RsUjRuS2o4a2krV1FpN0FvOE8zd2JVdEZsNG5IUmVRMUYzaFdOa21qTTlQT3pHYnZvc2diU2JQWW8xY1EvTmJ2bG45UXhGcHc1YlVjSW5BeFdtdm5MUnRFMnlmZzIvSWIrNDgrQ2pndTVGdEVva29IaUxudGhGcFFFTTdZZS9Md3phNDZJRGE0S3FwakdGTERkVGNKd2p0N3c3dnQrVEltbHYrU1ltQXRtd0lEQVFBQm8yQXdYakFNQmdOVkhSTUJBZjhFQWpBQU1BNEdBMVVkRHdFQi93UUVBd0lHd0RBZEJnTlZIUTRFRmdRVW5ZbVlrVS84WTcwU2ZBTlRoVmUyQWlDU3k1a3dId1lEVlIwakJCZ3dGb0FVblltWWtVLzhZNzBTZkFOVGhWZTJBaUNTeTVrd1FRWUpLb1pJaHZjTkFRRUtNRFNnRHpBTkJnbGdoa2dCWlFNRUFnTUZBS0VjTUJvR0NTcUdTSWIzRFFFQkNEQU5CZ2xnaGtnQlpRTUVBZ01GQUtJREFnRkFBNElCZ1FBaWw4TUJsbTlpb1FFZlgvbWw0SXNHZTRHV2g0b0svYXBFbTdEdnVnRzFmSXR4eC9SQ0hzNGVvYkNDWXZBNVpQZUUwK2llQU9jM1N2VlJEZ0YxMENvc0t0T0ZRYzNuekEwQUx2akp5Yk12VVRxSi9uN2FOYTZoU1hPRmlWOEhyNFIxT2JkTnBPUXhkVk5EYkpTeXNMbTYzWFk4NlZ1bldwb3hud1R1b0picEdYdjQzV0JsK3IyNVJZdFU1K3grMVBaMmt6eFFFWXJTS1U3OE9tdmRtMnVUd0E3Q3RFOG0wdWtERUZUellJWEZOQW1LWHVDNVp0NU5VdFl4ZHNRSXRhSnpRODhvTU1yeVlUWDFLTEUyZXNDZ3U1L3RRRWt1aysrdEF6d0RmK3dGc1A4ZnR2TjgxM2tTanJBbnhHKzluSFcxZURlWkkyVkFxZEhaNG4vOWxlVXVnMW56Q2h2NHVmdFFtczBydXJTYnYwRjVBamdmYWllR095ZXQrOGthUmFXOE5XYTZNQVh4ZkkrdEs2Q2hWYTJTbE9GQW5UUTI3aDA4amdKVHNNRCt4TUtQenF3VWNNSWVzd0hoWVVreHN0T3NmOTU5RmZHMEtFbnQzZ29VbTNlN3NDTTZ4KzlvaDFVOE1JS3FmY1JGVm9BWU9pVVVTQnk3bHVYZGdLTVdwWHM9Il0sIng1dCNTMjU2IjoiejFzVXdXaXFLQ21zbm1GV3E5SkxISkZ5QUdBVnljM1lJXzVjTXoyVlF3byJ9",
    "signature": "vtNN_aGqh4XhdiYx0TJg6QnJ4Uk1vgTbCvRzb5MtSHDh74ei2VRlr8heCyfb8NRWDIlsSaqCHQjonWGPXL-WJx5srnNkSfX5RZAyv4R4z8lslO5KiDJ-qyYsl4AMYRNDrit0LXkVxYldV2tcKhCQ0iY__YmbsMV8e88fQEqZuZTLoG5QvKJG15-d9YQdw9ZhWnsun0cQmxv26UW5yRQjOq0t--rS8p8pQv7qj_wtmc6uocc-mNo1QXFhImR3UjIioMIAYhaVwXrBk62lD_BIgcanJX_-HrEl_bCvdJqmOYBsAcJGEMsC3uO7-6TRzIIrQAITVkHpKFsUqbVfX2izAom7Tc15s42FHFlnSwKMuhIYOlvC3SOlR71sn1QpBtdoRZzRY645IMc689iOanqGghEiieUEQZCDKfX7zyxahLqL3YLmd63C0V4J9TjPSVs-ZiYta3zA2xSuGYczw7Vvr_OYQ8vmhY9e-Qq1dJ5-IlfkWC3JVhiDBP6I7yLLvoNT"
  }
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

        boolean ok = verifyDetachedBerlinGroup(berlinGroupWrapper, payloadJson);
        System.out.println("VALID (crypto-only, BG detached, pre-hash): " + ok);
    }
}