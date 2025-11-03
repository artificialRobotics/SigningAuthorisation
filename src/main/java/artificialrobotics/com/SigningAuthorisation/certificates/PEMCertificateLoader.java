package artificialrobotics.com.SigningAuthorisation.certificates;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

/** Konkrete Umsetzung für PEM-Dateien (-----BEGIN CERTIFICATE----- ...). */
public class PEMCertificateLoader extends CertificateLoader {

    public PEMCertificateLoader(Path directory, String fileName) {
        super(directory, fileName);
    }

    @Override
    public void load() throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(filePath())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(in);

            this.certificateChain = new ArrayList<>();
            for (java.security.cert.Certificate c : certs) {
                if (c instanceof X509Certificate x509) {
                    this.certificateChain.add(x509);
                }
            }

            if (!this.certificateChain.isEmpty()) {
                this.certificate = this.certificateChain.get(0); // erstes Zertifikat = End-Entity
            }
        }
    }
}