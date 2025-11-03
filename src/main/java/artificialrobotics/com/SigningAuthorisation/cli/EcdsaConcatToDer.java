package artificialrobotics.com.SigningAuthorisation.cli;

import java.math.BigInteger;
import java.util.Arrays;

public final class EcdsaConcatToDer {
  private EcdsaConcatToDer(){}
  public static byte[] concatToDer(byte[] concat, int fieldSize) {
    byte[] r = Arrays.copyOfRange(concat, 0, fieldSize);
    byte[] s = Arrays.copyOfRange(concat, fieldSize, 2*fieldSize);
    return derSeq(derInt(r), derInt(s));
  }
  private static byte[] derInt(byte[] x) {
    BigInteger bi = new BigInteger(1, x);
    byte[] v = bi.toByteArray();
    if (v[0] == 0 && v.length > 1 && (v[1] & 0x80) == 0) v = Arrays.copyOfRange(v,1,v.length);
    return concat(new byte[]{0x02}, derLen(v.length), v);
  }
  private static byte[] derSeq(byte[]... elems) {
    int len = 0; for (var e: elems) len += e.length;
    return concat(new byte[]{0x30}, derLen(len), concat(elems));
  }
  private static byte[] derLen(int len) {
    if (len < 0x80) return new byte[]{(byte)len};
    byte[] a = new byte[]{ (byte)(len>>>24),(byte)(len>>>16),(byte)(len>>>8),(byte)len };
    int off = 0; while (off<a.length && a[off]==0) off++;
    int n=a.length-off;
    byte[] out = new byte[1+n]; out[0]=(byte)(0x80|n);
    System.arraycopy(a,off,out,1,n); return out;
  }
  private static byte[] concat(byte[]... arrs) {
    int L=0; for (var a:arrs) L+=a.length;
    byte[] o=new byte[L]; int p=0;
    for (var a:arrs){System.arraycopy(a,0,o,p,a.length); p+=a.length;}
    return o;
  }
}
