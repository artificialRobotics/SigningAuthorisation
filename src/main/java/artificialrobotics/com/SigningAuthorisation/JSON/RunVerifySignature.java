package artificialrobotics.com.SigningAuthorisation.json;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;

public class RunVerifySignature {
	
	public static void main(String[] args) throws Exception {
		System.out.println(System.getProperty("user.dir"));
		
		new PEMCertificateLoader(FileSystems.getDefault().getPath(("user.dir"),"src\\resources"), "meine_test_gmbh_cert.pem");
		

	}

}
