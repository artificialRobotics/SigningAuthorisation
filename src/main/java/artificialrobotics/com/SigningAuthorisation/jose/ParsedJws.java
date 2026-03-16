package artificialrobotics.com.SigningAuthorisation.jose;

public final class ParsedJws {

    private final String protectedB64;
    private final String payloadB64;
    private final String signatureB64;
    private final boolean jsonSerialization;
    private final boolean detached;

    public ParsedJws(String protectedB64,
                     String payloadB64,
                     String signatureB64,
                     boolean jsonSerialization,
                     boolean detached) {
        this.protectedB64 = protectedB64;
        this.payloadB64 = payloadB64;
        this.signatureB64 = signatureB64;
        this.jsonSerialization = jsonSerialization;
        this.detached = detached;
    }

    public String getProtectedB64() {
        return protectedB64;
    }

    public String getPayloadB64() {
        return payloadB64;
    }

    public String getSignatureB64() {
        return signatureB64;
    }

    public boolean isJsonSerialization() {
        return jsonSerialization;
    }

    public boolean isDetached() {
        return detached;
    }
}