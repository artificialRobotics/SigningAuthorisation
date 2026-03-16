package artificialrobotics.com.SigningAuthorisation.xades;

import artificialrobotics.com.SigningAuthorisation.certificates.CertificateLoader;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.signingKeys.KeystorePrivateKeyLoader;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PrivateKeyFactory;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public final class XadesKeyMaterialResolver {

    public XadesResolvedKeyMaterial resolve(XadesSignRequest request) throws Exception {
        if (request.usesKeystore()) {
            return resolveFromKeystore(request);
        }
        return resolveFromFiles(request);
    }

    private XadesResolvedKeyMaterial resolveFromKeystore(XadesSignRequest request) throws Exception {
        Path ksPath = request.getKeystorePath().toAbsolutePath().normalize();
        Path ksDir = ksPath.getParent();
        if (ksDir == null) {
            ksDir = Path.of(".").toAbsolutePath();
        }

        KeystorePrivateKeyLoader loader = new KeystorePrivateKeyLoader(
            ksDir,
            ksPath.getFileName().toString(),
            request.getKeystoreType(),
            request.getKeystorePassword() != null ? request.getKeystorePassword().toCharArray() : null,
            request.getKeyAlias(),
            request.getKeyPassword() != null && !request.getKeyPassword().isBlank()
                ? request.getKeyPassword().toCharArray()
                : null
        );

        loader.load();

        PrivateKey privateKey = loader.getPrivateKey();
        List<X509Certificate> chain = loader.getCertificateChain();
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("No certificate chain found in keystore for alias: " + request.getKeyAlias());
        }

        X509Certificate signingCertificate = chain.get(0);
        return new XadesResolvedKeyMaterial(privateKey, signingCertificate, chain);
    }

    private XadesResolvedKeyMaterial resolveFromFiles(XadesSignRequest request) throws Exception {
        PrivateKey privateKey = PrivateKeyFactory.load(request.getKeyDir(), request.getKeyFile());

        CertificateLoader certificateLoader = new PEMCertificateLoader(request.getCertDir(), request.getCertFile());
        certificateLoader.load();

        List<X509Certificate> chain = certificateLoader.getCertificateChain();
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("No X.509 certificate found in PEM file: " +
                request.getCertDir().resolve(request.getCertFile()).toAbsolutePath());
        }

        X509Certificate signingCertificate = certificateLoader.getCertificate();
        if (signingCertificate == null) {
            signingCertificate = chain.get(0);
        }

        return new XadesResolvedKeyMaterial(privateKey, signingCertificate, chain);
    }
}