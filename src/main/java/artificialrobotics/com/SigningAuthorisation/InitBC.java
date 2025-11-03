package artificialrobotics.com.SigningAuthorisation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;


/**
 * Import this class when you want to use BouncyCastle
 */
public class InitBC {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  //For test only: Check if BouncyCastle libraries are available 
  public static void main(String[] args) {
    System.out.println("BC available: " + Security.getProvider("BC"));
  }
}