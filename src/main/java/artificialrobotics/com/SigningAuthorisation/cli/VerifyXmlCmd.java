package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.xades.XadesVerifyRequest;
import artificialrobotics.com.SigningAuthorisation.xades.XadesVerifyService;
import picocli.CommandLine;

import java.nio.file.Path;

@CommandLine.Command(
    name = "verify-xml",
    description = "Validates a detached XAdES XML signature document against the original XML payload."
)
public class VerifyXmlCmd implements Runnable {

    @CommandLine.Option(
        names = "--format",
        required = true,
        description = "Currently only supported value: xades"
    )
    String format;

    @CommandLine.Option(
        names = "--in",
        required = true,
        description = "Detached XAdES XML signature document."
    )
    Path signatureFile;

    @CommandLine.Option(
        names = "--payload",
        required = true,
        description = "Original detached XML payload file."
    )
    Path payloadFile;

    @CommandLine.Option(
        names = "--truststore",
        required = true,
        description = "Truststore file for DSS validation (PKCS12/JKS)."
    )
    Path truststorePath;

    @CommandLine.Option(
        names = "--truststoreType",
        description = "Truststore type: PKCS12 | JKS (default: PKCS12)"
    )
    String truststoreType = "PKCS12";

    @CommandLine.Option(
        names = "--truststorePassword",
        required = true,
        description = "Truststore password for DSS validation."
    )
    String truststorePassword;

    @CommandLine.Option(
        names = "--validationPolicy",
        description = "Optional custom DSS validation policy XML file."
    )
    Path validationPolicyFile;

    @CommandLine.Option(
        names = "--debug",
        description = "Enable debug output."
    )
    boolean debug;

    @Override
    public void run() {
        try {
            new InitBC();

            XadesVerifyRequest request = new XadesVerifyRequest(
                format,
                signatureFile,
                payloadFile,
                truststorePath,
                truststoreType,
                truststorePassword,
                validationPolicyFile,
                debug
            );

            request.validate();

            XadesVerifyService service = new XadesVerifyService();
            service.verify(request);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }
}