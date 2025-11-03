package artificialrobotics.com.SigningAuthorisation.signingKeys;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Lädt RSA Public Key aus XML (RSAKeyValue mit Modulus/Exponent). */
public class RSAXmlPublicKeyLoader extends PublicKeyLoader {

    public RSAXmlPublicKeyLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws Exception {
        String xml = readFileString();
        BigInteger n = b64Xml(xml, "Modulus");
        BigInteger e = b64Xml(xml, "Exponent");
        RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static BigInteger b64Xml(String xml, String tag) {
        Matcher m = Pattern.compile("<"+tag+">([^<]+)</"+tag+">").matcher(xml);
        if (!m.find()) throw new IllegalArgumentException("Missing <"+tag+"> in XML");
        return new BigInteger(1, Base64.getDecoder().decode(m.group(1)));
        }
}