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
 *   4) Extract "alg" and check it is PS512 or ES512
 *   5) Canonicalize payload using JCS and Base64URL-encode it (mirrors signer)
 *   6) Build signing input: ASCII(protectedB64 + "." + payloadB64)
 *   7) Compute SHA-512 over signing input
 *   8) Decode signature bytes
 *   9) Single verification call: verifySignature(protected, signature, messageToVerify)
 *
 * NOTE:
 *   - messageToVerify == SHA-512(signingInput)
 *   - For PS512: messageToVerify is the RSA-PSS pre-hash
 *   - For ES512: messageToVerify is the final ECDSA message (NONEwithECDSA, no internal hashing)
 */
public class ExampleVerifyBerlinGroup {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Pattern SUB_PATTERN =
            Pattern.compile("\"sub\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern ALG_PATTERN =
            Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]*)\"");

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

        // 4) Extract alg and check it is PS512 or ES512
        String alg = extractClaim(protectedJson, ALG_PATTERN);
        if (alg == null || alg.isEmpty()) {
            throw new IllegalArgumentException("Missing or empty 'alg' claim in protected header.");
        }
        if (!"PS512".equals(alg) && !"ES512".equals(alg)) {
            throw new IllegalArgumentException("Unsupported alg in protected header: " + alg);
        }

        // 5) Canonicalize payload using JCS and Base64URL-encode it (mirrors signer)
        String payloadB64 = payloadJsonToBase64UrlJcs(payloadJson);

        // 6) Build signing input (ASCII) as defined by RFC 7515 §5
        byte[] signingInput = (bg.protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);

        // 7) Compute SHA-512 over signing input
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(signingInput);

        // 8) Decode signature bytes
        byte[] sig = Base64.getUrlDecoder().decode(bg.signatureB64);

        // 9) Single verification call:
        //    verifySignature(protected, signature, messageToVerify)
        return verifySignature(protectedJson, sig, digest);
    }

    /* ---------- Step 9: single verification method ---------- */

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
     * Uses NONEwithECDSA via BC provider.
     *
     * Signature is expected to be DER-encoded (ASN.1 SEQUENCE r,s) as produced by JCA.
     */
    private static boolean verifyEs512NoHash(PublicKey pub, byte[] digest, byte[] sigDer) throws Exception {
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

    /* ---------- Demo ---------- */

    public static void main(String[] args) throws Exception {

    	//please insert here the Berlin Group signatureDate 
        String berlinGroupWrapper = """
{
  "signatureData": {
    "protected": "eyJhbGciOiJFUzUxMiIsInNpZ1QiOiIyMDI2LTAyLTAxVDE5OjQzOjI4WiIsInN1YiI6Im15UGF5bWVudFJlc291cmNlSWQxMjM0NSIsImNhbm9uQWxnIjoiaHR0cDovL2pzb24tY2Fub25pY2FsaXphdGlvbi5vcmcvYWxnb3JpdGhtIiwieDV1IjoiaHR0cHM6Ly9leGFtcGxlLm9yZy9jZXJ0cy9tZWluZV90ZXN0X2dtYmhfY2VydC5wZW0iLCJjcml0IjpbImNhbm9uQWxnIiwic2lnVCIsInN1YiJdLCJ4NWMiOlsiTUlJQ3VqQ0NBaHVnQXdJQkFnSVVEZCtnQU1sV3pMTCtUMmJia3NmeC9ab3FZdjB3Q2dZSUtvWkl6ajBFQXdRd2FERUxNQWtHQTFVRUJoTUNSRVV4RkRBU0JnTlZCQW9NQzAxMWMzUmxjaUJIYldKSU1SUXdFZ1lEVlFRRERBdE5kWE4wWlhJZ1IyMWlTREVUTUJFR0ExVUVDd3dLVUdGNWJXVnVkRWgxWWpFWU1CWUdBMVVFWVF3UFRsUlNSRVV0U0ZKQ01USXpORFUyTUI0WERUSTJNREl3TVRFM05EUTFObG9YRFRNMk1ERXpNREUzTkRRMU5sb3dhREVMTUFrR0ExVUVCaE1DUkVVeEZEQVNCZ05WQkFvTUMwMTFjM1JsY2lCSGJXSklNUlF3RWdZRFZRUUREQXROZFhOMFpYSWdSMjFpU0RFVE1CRUdBMVVFQ3d3S1VHRjViV1Z1ZEVoMVlqRVlNQllHQTFVRVlRd1BUbFJTUkVVdFNGSkNNVEl6TkRVMk1JR2JNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWpBNEdHQUFRQXlwVGlmczZ6RVo0NUFPRitFV3VBYXN2eXpMYmFQR3Z3SDIwSHd2cUZMNXFSMEtZTURaejczWVVNeWQzSmZvQVFjSUN3bTZQWHlFWHVRMzM0aTV1dTMzVUJGNFQ4QTFTdEh2M0JRWGtzanhLVFgrNVoyZlFGOE1XbXk2U2tvQlE3RVZTUUJHTXduRUJiSG5vZm9mTGREQW5RMEhQV1g0YkpyTUdqTzZNcURycitTcktqWURCZU1Bd0dBMVVkRXdFQi93UUNNQUF3RGdZRFZSMFBBUUgvQkFRREFnYkFNQjBHQTFVZERnUVdCQlQ0NmdybU9BNDVvMUpKdUhRNFlST2psRWZpYVRBZkJnTlZIU01FR0RBV2dCVDQ2Z3JtT0E0NW8xSkp1SFE0WVJPamxFZmlhVEFLQmdncWhrak9QUVFEQkFPQmpBQXdnWWdDUWdEZlVHWFQ2cnFWTHZTVU5XRUU5TEQ2VjFlVno0L1FEN0FkY0ZpMk5IZFZXRnplUGE2dWZRVDFCMFg2eDBSb0JQVm5ZWmxsb05YQUI5Z0x1bllYUnVrWERRSkNBSmtDcmNXNGdkNmpOTnVOWjBTenJHTHRTYWlmVjA3NXBCZUdLTkxBalg2N3AvRno5UllnUC95Y09tYkI2bHhKM0tDVDFNVEJ0NEh4RmJOYVloSS90SWpQIl19",
    "signature": "MIGHAkIAp2CKpqEH0pY1yYTyx7-qJAkV24m4HorISUpfEd6rstrZqLzwLuO9DU5eMtLkk7qg1C4Py1C82lmGPIF23dOixKoCQWtBlRPAo_d7D4J284Tyj1lGEzWLV2SDVWp9P2iHElpiUzS-KiMSsCJdZsw50GRzJNr62TGnX55JFQIrORL4_rWr"
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
        System.out.println("VALID (crypto-only, PS512, pre-hash): " + ok);
    }
}