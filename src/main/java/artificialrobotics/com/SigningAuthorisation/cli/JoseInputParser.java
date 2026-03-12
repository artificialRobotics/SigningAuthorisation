package artificialrobotics.com.SigningAuthorisation.cli;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class JoseInputParser {

    private JoseInputParser() {
    }

    public static ParsedJws parse(String content) {
        if (isJsonSerialization(content)) {
            String protectedB64 = extractJsonValue(content, "\"protected\"");
            String signatureB64 = extractJsonValue(content, "\"signature\"");
            String payloadB64 = content.contains("\"payload\"")
                    ? extractJsonValue(content, "\"payload\"")
                    : null;

            return new ParsedJws(
                    protectedB64,
                    payloadB64,
                    signatureB64,
                    true,
                    payloadB64 == null || payloadB64.isEmpty()
            );
        }

        String[] parts = content.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
        }

        String protectedB64 = parts[0];
        String payloadB64 = parts[1];
        String signatureB64 = parts[2];

        return new ParsedJws(
                protectedB64,
                payloadB64,
                signatureB64,
                false,
                payloadB64 == null || payloadB64.isEmpty()
        );
    }

    public static boolean isJsonSerialization(String s) {
        return s.contains("\"protected\"") && s.contains("\"signature\"");
    }

    public static boolean isBerlinGroupSerialization(String s) {
        return s.contains("\"signatureData\"")
                && s.contains("\"protected\"")
                && s.contains("\"signature\"");
    }

    public static boolean isPlainJoseJsonSerialization(String s) {
        return s.contains("\"protected\"")
                && s.contains("\"signature\"")
                && !s.contains("\"signatureData\"");
    }

    public static String extractJsonValue(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) {
            throw new IllegalArgumentException("Missing JSON field " + keyWithQuotes);
        }

        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon + 1);
        int q2 = json.indexOf('"', q1 + 1);

        if (colon < 0 || q1 < 0 || q2 < 0) {
            throw new IllegalArgumentException("Malformed JSON near " + keyWithQuotes);
        }

        return json.substring(q1 + 1, q2);
    }

    public static String extractJsonValueLenient(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) {
            return null;
        }

        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon + 1);
        int q2 = json.indexOf('"', q1 + 1);

        if (colon < 0 || q1 < 0 || q2 < 0) {
            return null;
        }

        return json.substring(q1 + 1, q2);
    }

    public static String extractFirstStringFromJsonArray(String json, String keyWithQuotes) {
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

    public static String extractProtectedHeaderJson(String content) {
        ParsedJws parsed = parse(content);
        return new String(
                Base64.getUrlDecoder().decode(parsed.getProtectedB64()),
                StandardCharsets.UTF_8
        );
    }

    public static String toJoseJsonForDss(String content) {
        if (isBerlinGroupSerialization(content)) {
            String protectedB64 = extractJsonValue(content, "\"protected\"");
            String signatureB64 = extractJsonValue(content, "\"signature\"");

            return """
                    {
                      "protected":"%s",
                      "signature":"%s"
                    }
                    """.formatted(protectedB64, signatureB64).trim();
        }

        if (isPlainJoseJsonSerialization(content)) {
            return content;
        }

        ParsedJws parsed = parse(content);

        if (parsed.getPayloadB64() == null || parsed.getPayloadB64().isEmpty()) {
            return """
                    {
                      "protected":"%s",
                      "signature":"%s"
                    }
                    """.formatted(parsed.getProtectedB64(), parsed.getSignatureB64()).trim();
        }

        return """
                {
                  "payload":"%s",
                  "protected":"%s",
                  "signature":"%s"
                }
                """.formatted(
                parsed.getPayloadB64(),
                parsed.getProtectedB64(),
                parsed.getSignatureB64()
        ).trim();
    }
}