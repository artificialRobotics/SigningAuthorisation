package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Lädt RSA Private Key aus XML-Format (z. B. .NET RSAKeyValue). */
public class RSAXmlPrivateKeyLoader extends PrivateKeyLoader {

    public RSAXmlPrivateKeyLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws Exception {
        String xml = readFileString();

        // Pflichtfelder im XML: Modulus, Exponent (public), D, P, Q, DP, DQ, InverseQ
        BigInteger n  = b64Xml(xml, "Modulus");
        BigInteger e  = b64Xml(xml, "Exponent");
        BigInteger d  = b64Xml(xml, "D");
        BigInteger p  = b64Xml(xml, "P");
        BigInteger q  = b64Xml(xml, "Q");
        BigInteger dp = b64Xml(xml, "DP");
        BigInteger dq = b64Xml(xml, "DQ");
        BigInteger qi = b64Xml(xml, "InverseQ");

        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
        this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static BigInteger b64Xml(String xml, String tag) {
        String pattern = "<" + tag + ">([^<]+)</" + tag + ">";
        Matcher m = Pattern.compile(pattern).matcher(xml);
        if (!m.find()) throw new IllegalArgumentException("Missing <" + tag + "> in XML");
        byte[] bytes = Base64.getDecoder().decode(m.group(1));
        return new BigInteger(1, bytes);
    }
}
