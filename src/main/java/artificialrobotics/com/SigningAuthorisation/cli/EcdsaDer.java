package artificialrobotics.com.SigningAuthorisation.cli;

import java.math.BigInteger;
import java.util.Arrays;

public final class EcdsaDer {
  private EcdsaDer(){}

  public static byte[] transcodeDerToConcat(byte[] der, int fieldSize) {
    // sehr kompakte DER-Parser für ECDSA-Signaturen: SEQ { r INTEGER, s INTEGER }
    if (der[0] != 0x30) throw new IllegalArgumentException("Not DER SEQUENCE");
    int idx = 2; // skip tag+len (heuristisch, ausreichend für normale Längen)
    if (der[1] < 0) idx = 3; // lange Länge – simple Heuristik
    if (der[idx++] != 0x02) throw new IllegalArgumentException("Missing r");
    int rLen = der[idx++] & 0xff;
    byte[] r = Arrays.copyOfRange(der, idx, idx+rLen); idx+=rLen;
    if (der[idx++] != 0x02) throw new IllegalArgumentException("Missing s");
    int sLen = der[idx++] & 0xff;
    byte[] s = Arrays.copyOfRange(der, idx, idx+sLen);

    byte[] rc = unsignedFixed(r, fieldSize);
    byte[] sc = unsignedFixed(s, fieldSize);
    byte[] out = new byte[fieldSize*2];
    System.arraycopy(rc,0,out,0,fieldSize);
    System.arraycopy(sc,0,out,fieldSize,fieldSize);
    return out;
  }

  private static byte[] unsignedFixed(byte[] v, int size) {
    BigInteger bi = new BigInteger(1, v);
    byte[] tmp = bi.toByteArray();
    if (tmp.length == size) return tmp;
    byte[] out = new byte[size];
    // copy right-aligned
    System.arraycopy(tmp, Math.max(0,tmp.length-size), out, Math.max(0,size-tmp.length), Math.min(size,tmp.length));
    return out;
  }
}
