package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.xades.XadesKeyMaterialResolver;
import artificialrobotics.com.SigningAuthorisation.xades.XadesSignRequest;
import artificialrobotics.com.SigningAuthorisation.xades.XadesSignService;
import artificialrobotics.com.SigningAuthorisation.xades.XadesSignatureParametersFactory;
import picocli.CommandLine;

import java.nio.file.Path;

@CommandLine.Command(
    name = "sign-xml",
    description = "Creates a detached XAdES Baseline-B signature as a separate XML signature document. The original XML payload remains unchanged."
)
public class SignXmlCmd implements Runnable {

    @CommandLine.Option(
        names = "--format",
        required = true,
        description = "Currently only supported value: xades"
    )
    String format;

    @CommandLine.Option(
        names = "--alg",
        required = true,
        description = "Signature algorithm. Supported: RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384 | ES512"
    )
    String alg;

    @CommandLine.Option(
        names = "--payload",
        required = true,
        description = "Input XML payload file to be signed (remains unchanged)."
    )
    Path payloadFile;

    @CommandLine.Option(
        names = "--out",
        required = true,
        description = "Output file for the detached XAdES XML signature document."
    )
    Path outFile;

    @CommandLine.Option(
        names = "--referenceURI",
        description = "Optional full external reference URI for the detached ds:Reference. Example: urn:paymenthub:pain001:1234567890"
    )
    String referenceURI;

    @CommandLine.Option(names = "--key-dir")
    Path keyDir;

    @CommandLine.Option(names = "--key-file")
    String keyFile;

    @CommandLine.Option(names = "--keystore", description = "Path to keystore file (.p12/.pfx/.jks)")
    Path keystorePath;

    @CommandLine.Option(names = "--keystoreType", description = "Keystore type: PKCS12 | JKS (default: PKCS12)")
    String keystoreType = "PKCS12";

    @CommandLine.Option(names = "--keystorePassword", description = "Keystore password")
    String keystorePassword;

    @CommandLine.Option(names = "--keyAlias", description = "Alias of the private key entry in keystore")
    String keyAlias;

    @CommandLine.Option(names = "--keyPassword", description = "Private key password (if different from keystore password)")
    String keyPassword;

    @CommandLine.Option(names = "--cert-dir", description = "Directory containing the signer certificate / chain PEM file.")
    Path certDir;

    @CommandLine.Option(names = "--cert-file", description = "PEM file containing signer certificate (and optionally chain).")
    String certFile;

    @CommandLine.Option(names = "--debug", description = "Enable debug output.")
    boolean debug;

    @Override
    public void run() {
        try {
            new InitBC();

            XadesSignRequest request = new XadesSignRequest(
                format,
                alg,
                payloadFile,
                outFile,
                referenceURI,
                keyDir,
                keyFile,
                keystorePath,
                keystoreType,
                keystorePassword,
                keyAlias,
                keyPassword,
                certDir,
                certFile,
                debug
            );

            request.validate();

            XadesSignService service = new XadesSignService(
                new XadesKeyMaterialResolver(),
                new XadesSignatureParametersFactory()
            );

            service.sign(request);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }
}