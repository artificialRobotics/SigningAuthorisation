package artificialrobotics.com.SigningAuthorisation.jose;

import java.util.Arrays;

/**
 * Utilities to transcode ECDSA signatures between:
 *  - DER (SEQUENCE of two INTEGERs r and s)  <->  JWS raw concatenation (R||S)
 *
 * References:
 *  - RFC 7515 (JWS) - ECDSA signatures use the concatenation of R and S
 *  - X.690 (DER) - INTEGER and SEQUENCE encoding rules
 */
public final class EcdsaDer {

    private EcdsaDer() {}

    /**
     * Transcodes a DER-encoded ECDSA signature to the JWS raw concatenation (R||S).
     *
     * @param derSig         DER-encoded signature: SEQUENCE { INTEGER r, INTEGER s }
     * @param fieldSizeBytes size of the field in bytes: P-256 -> 32, P-384 -> 48, P-521 -> 66
     * @return raw signature R||S (length = 2*fieldSizeBytes)
     */
    public static byte[] transcodeDerToConcat(byte[] derSig, int fieldSizeBytes) {
        if (derSig == null || derSig.length < 8) {
            throw new IllegalArgumentException("Invalid DER signature (too short).");
        }
        int idx = 0;

        // SEQUENCE
        if (derSig[idx++] != 0x30) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature: no SEQUENCE.");
        }
        int seqLen = readDerLength(derSig, idx);
        int lenBytes = derLenByteCount(derSig[idx]);
        idx += lenBytes;

        if (seqLen < 0 || idx + seqLen != derSig.length) {
            // Be tolerant to trailing zeros? No: keep strict.
            if (idx + seqLen > derSig.length) {
                throw new IllegalArgumentException("Invalid DER length for SEQUENCE.");
            }
        }

        // INTEGER r
        if (derSig[idx++] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature: expected INTEGER (r).");
        }
        int rLen = readDerLength(derSig, idx);
        lenBytes = derLenByteCount(derSig[idx]);
        idx += lenBytes;

        if (rLen <= 0 || idx + rLen > derSig.length) {
            throw new IllegalArgumentException("Invalid r length in DER signature.");
        }
        byte[] rBytes = Arrays.copyOfRange(derSig, idx, idx + rLen);
        idx += rLen;

        // INTEGER s
        if (derSig[idx++] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature: expected INTEGER (s).");
        }
        int sLen = readDerLength(derSig, idx);
        lenBytes = derLenByteCount(derSig[idx]);
        idx += lenBytes;

        if (sLen <= 0 || idx + sLen > derSig.length) {
            throw new IllegalArgumentException("Invalid s length in DER signature.");
        }
        byte[] sBytes = Arrays.copyOfRange(derSig, idx, idx + sLen);

        // Convert DER INTEGER (two's complement with potential leading 0x00) to unsigned fixed width
        byte[] rFixed = unsignedIntegerToFixed(rBytes, fieldSizeBytes);
        byte[] sFixed = unsignedIntegerToFixed(sBytes, fieldSizeBytes);

        byte[] out = new byte[fieldSizeBytes * 2];
        System.arraycopy(rFixed, 0, out, 0, fieldSizeBytes);
        System.arraycopy(sFixed, 0, out, fieldSizeBytes, fieldSizeBytes);
        return out;
        }

    /**
     * Transcodes a JWS raw concatenation (R||S) to a DER-encoded ECDSA signature.
     *
     * @param concatSig      raw signature (R||S). Length must be 2*fieldSizeBytes.
     * @param fieldSizeBytes size of the field in bytes: P-256 -> 32, P-384 -> 48, P-521 -> 66
     * @return DER-encoded SEQUENCE { INTEGER r, INTEGER s }
     */
    public static byte[] transcodeConcatToDer(byte[] concatSig, int fieldSizeBytes) {
        if (concatSig == null || concatSig.length != 2 * fieldSizeBytes) {
            throw new IllegalArgumentException("Invalid raw ECDSA signature length.");
        }
        byte[] r = Arrays.copyOfRange(concatSig, 0, fieldSizeBytes);
        byte[] s = Arrays.copyOfRange(concatSig, fieldSizeBytes, 2 * fieldSizeBytes);

        // Convert fixed-width unsigned to minimal DER INTEGER (add leading 0x00 if MSB set)
        byte[] rDerInt = encodeDerInteger(stripLeadingZeros(r));
        byte[] sDerInt = encodeDerInteger(stripLeadingZeros(s));

        int seqPayloadLen = rDerInt.length + sDerInt.length;
        byte[] seqLen = encodeDerLength(seqPayloadLen);

        byte[] out = new byte[1 + seqLen.length + seqPayloadLen];
        int pos = 0;
        out[pos++] = 0x30; // SEQUENCE
        System.arraycopy(seqLen, 0, out, pos, seqLen.length);
        pos += seqLen.length;

        System.arraycopy(rDerInt, 0, out, pos, rDerInt.length);
        pos += rDerInt.length;
        System.arraycopy(sDerInt, 0, out, pos, sDerInt.length);

        return out;
    }

    /* ------------------------- DER helpers ------------------------- */

    private static int readDerLength(byte[] buf, int off) {
        int first = buf[off] & 0xFF;
        if ((first & 0x80) == 0) {
            return first; // short form
        }
        int num = first & 0x7F;
        if (num == 0 || num > 4) {
            throw new IllegalArgumentException("Unsupported DER length form.");
        }
        if (off + 1 + num > buf.length) {
            throw new IllegalArgumentException("DER length overruns buffer.");
        }
        int val = 0;
        for (int i = 0; i < num; i++) {
            val = (val << 8) | (buf[off + 1 + i] & 0xFF);
        }
        return val;
    }

    private static int derLenByteCount(byte b0) {
        int first = b0 & 0xFF;
        if ((first & 0x80) == 0) return 1;
        int num = first & 0x7F;
        return 1 + num;
    }

    private static byte[] encodeDerLength(int len) {
        if (len < 0) throw new IllegalArgumentException("Negative length.");
        if (len < 0x80) {
            return new byte[]{ (byte) len };
        }
        // long form
        byte[] tmp = new byte[4];
        int p = 4;
        int v = len;
        while (v > 0) {
            tmp[--p] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        int num = 4 - p;
        byte[] out = new byte[1 + num];
        out[0] = (byte) (0x80 | num);
        System.arraycopy(tmp, p, out, 1, num);
        return out;
    }

    private static byte[] encodeDerInteger(byte[] unsignedMagnitude) {
        // unsignedMagnitude: minimal magnitude (no leading zeros) and positive
        if (unsignedMagnitude.length == 0) {
            // INTEGER 0
            return new byte[]{ 0x02, 0x01, 0x00 };
        }
        boolean msbSet = (unsignedMagnitude[0] & 0x80) != 0;
        int len = unsignedMagnitude.length + (msbSet ? 1 : 0);
        byte[] out = new byte[2 + len];
        out[0] = 0x02; // INTEGER
        out[1] = (byte) len;
        int pos = 2;
        if (msbSet) {
            out[pos++] = 0x00; // add leading 0x00 to enforce positive
        }
        System.arraycopy(unsignedMagnitude, 0, out, pos, unsignedMagnitude.length);
        return out;
    }

    /* ------------------------- Integer helpers ------------------------- */

    /**
     * Convert DER INTEGER bytes (two's complement, possibly with leading 0x00) to a fixed-length
     * unsigned big-endian representation, left-padded with zeros to fieldSizeBytes.
     */
    private static byte[] unsignedIntegerToFixed(byte[] derInteger, int fieldSizeBytes) {
        // Remove leading 0x00 bytes (sign padding)
        byte[] mag = stripLeadingZeros(derInteger);

        if (mag.length > fieldSizeBytes) {
            // If there's a single leading 0x00 that we removed, but still longer -> invalid.
            // Allow case where it is exactly fieldSizeBytes or shorter.
            // Sometimes DER INTEGER can still be 1 byte longer than field (only sign 0x00) → handled by stripLeadingZeros.
            throw new IllegalArgumentException("INTEGER too large for field size.");
        }

        byte[] out = new byte[fieldSizeBytes];
        System.arraycopy(mag, 0, out, fieldSizeBytes - mag.length, mag.length);
        return out;
    }

    private static byte[] stripLeadingZeros(byte[] v) {
        int i = 0;
        while (i < v.length - 1 && v[i] == 0x00) i++;
        return (i == 0) ? v : Arrays.copyOfRange(v, i, v.length);
    }

    /* ------------------------- Convenience ------------------------- */

    /**
     * Helper: choose field size from a JWS alg ("ES256","ES384","ES512").
     */
    public static int fieldSizeBytesForAlg(String alg) {
        if ("ES256".equals(alg)) return 32;
        if ("ES384".equals(alg)) return 48;
        if ("ES512".equals(alg)) return 66; // NIST P-521
        throw new IllegalArgumentException("Unsupported ECDSA alg: " + alg);
    }

    /**
     * Safe DER→raw using alg string.
     */
    public static byte[] derToConcat(byte[] derSig, String alg) {
        return transcodeDerToConcat(derSig, fieldSizeBytesForAlg(alg));
    }

    /**
     * Safe raw→DER using alg string.
     */
    public static byte[] concatToDer(byte[] rawSig, String alg) {
        return transcodeConcatToDer(rawSig, fieldSizeBytesForAlg(alg));
    }
}
