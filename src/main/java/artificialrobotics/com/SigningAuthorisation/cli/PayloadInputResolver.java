package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public final class PayloadInputResolver {

    public PayloadInputData loadDetachedPayload(Path payloadFile, String canonicalizePayload) throws Exception {
        if (payloadFile == null) {
            throw new IllegalArgumentException("Detached payload file is required.");
        }

        byte[] raw = Files.readAllBytes(payloadFile);

        boolean doCanonicalize = canonicalizePayload != null
                && canonicalizePayload.equalsIgnoreCase("jcs");

        if (!doCanonicalize) {
            return new PayloadInputData(raw, false, null);
        }

        String asText = new String(raw, StandardCharsets.UTF_8);
        if (!looksLikeJson(asText)) {
            throw new IllegalArgumentException(
                    "--canonicalize-payload=jcs requires a JSON payload file (object or array)."
            );
        }

        String canonical = JsonCanonicalizerJcs.canonicalize(asText);
        byte[] canonicalBytes = canonical.getBytes(StandardCharsets.UTF_8);

        return new PayloadInputData(canonicalBytes, true, "jcs");
    }

    public byte[] loadPayloadHash(Path hashFile, String alg) throws Exception {
        if (hashFile == null) {
            throw new IllegalArgumentException("Hash file is required.");
        }

        String content = Files.readString(hashFile, StandardCharsets.UTF_8).trim();
        if (content.isEmpty()) {
            throw new IllegalArgumentException("Hash file is empty: " + hashFile);
        }

        byte[] digest = decodeBase64OrBase64Url(content);

        int expectedLen = switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512", "RS512", "PS512" -> 64;
            default -> throw new IllegalArgumentException("Unsupported alg for hash file: " + alg);
        };

        if (digest.length != expectedLen) {
            throw new IllegalArgumentException(
                    "Unexpected hash length in --payloadHashFile for " + alg
                            + ". Expected " + expectedLen + " bytes, got " + digest.length + "."
            );
        }

        return digest;
    }

    public byte[] decodeBase64OrBase64Url(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            return Base64.getUrlDecoder().decode(value);
        }
    }

    public boolean looksLikeJson(String s) {
        if (s == null) {
            return false;
        }

        int i = 0;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }

        if (i >= s.length()) {
            return false;
        }

        char c = s.charAt(i);
        return c == '{' || c == '[';
    }
}