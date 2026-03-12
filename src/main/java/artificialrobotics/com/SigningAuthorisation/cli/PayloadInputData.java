package artificialrobotics.com.SigningAuthorisation.cli;

public final class PayloadInputData {

    private final byte[] bytes;
    private final boolean canonicalized;
    private final String canonicalization;

    public PayloadInputData(byte[] bytes, boolean canonicalized, String canonicalization) {
        this.bytes = bytes;
        this.canonicalized = canonicalized;
        this.canonicalization = canonicalization;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public boolean isCanonicalized() {
        return canonicalized;
    }

    public String getCanonicalization() {
        return canonicalization;
    }
}