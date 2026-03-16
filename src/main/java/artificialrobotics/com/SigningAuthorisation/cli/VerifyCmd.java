package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.verify.VerifyCryptoService;
import artificialrobotics.com.SigningAuthorisation.verify.VerifyDebugSupport;
import artificialrobotics.com.SigningAuthorisation.verify.VerifyDssService;
import artificialrobotics.com.SigningAuthorisation.verify.VerifyOrchestrator;
import artificialrobotics.com.SigningAuthorisation.verify.VerifyRequest;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

@CommandLine.Command(
        name = "verify",
        description = "Verify JWS/JAdES (crypto-only, eIDAS/DSS, or mixed)."
)
public class VerifyCmd implements Runnable {

    @CommandLine.Option(names = "--mode", required = true, description = "crypto | eidas | mixed")
    String mode;

    @CommandLine.Option(names = "--alg", required = true, description = "RS512 | PS512 | ES256 | ES384 | ES512 | ph")
    String alg;

    @CommandLine.Option(names = "--in", required = true, description = "JWS input file (compact OR JSON serialization; BG wrapper supported).")
    Path inFile;

    @CommandLine.Option(names = "--pub-dir", description = "Directory of public key / certificate")
    Path pubDir;

    @CommandLine.Option(names = "--pub-file", description = "File name of public key / certificate")
    String pubFile;

    @CommandLine.Option(names = "--detached", description = "Treat input as detached JWS.")
    boolean detached;

    @CommandLine.Option(names = "--payload", description = "Detached payload file (raw bytes).")
    Path payloadFile;

    @CommandLine.Option(
            names = "--payloadHashFile",
            description = "Crypto or mixed mode only: file containing Base64/Base64URL encoded hash of the signing input."
    )
    Path payloadHashFile;

    @CommandLine.Option(
            names = "--canonicalize-payload",
            description = "Apply canonicalization to detached payload before verification. Supported value: jcs"
    )
    String canonicalizePayload;

    @CommandLine.Option(names = "--truststore", description = "Truststore file for DSS verification (PKCS12/JKS).")
    Path truststorePath;

    @CommandLine.Option(names = "--truststoreType", description = "Truststore type: PKCS12 | JKS (default: PKCS12)")
    String truststoreType = "PKCS12";

    @CommandLine.Option(names = "--truststorePassword", description = "Truststore password for DSS verification.")
    String truststorePassword;

    @CommandLine.Option(names = "--validationPolicy", description = "Custom DSS validation policy XML file.")
    Path validationPolicyFile;

    @CommandLine.Option(names = "--debug", description = "Print additional debug information.")
    boolean debug;

    @Override
    public void run() {
        try {
            new InitBC();

            VerifyRequest request = buildRequest();
            String content = Files.readString(request.getInFile(), StandardCharsets.UTF_8).trim();

            PayloadInputResolver payloadInputResolver = new PayloadInputResolver();
            VerifyDebugSupport debugSupport = new VerifyDebugSupport(() -> request.isDebug());
            VerifyCryptoService cryptoService = new VerifyCryptoService(payloadInputResolver, debugSupport);
            VerifyDssService dssService = new VerifyDssService(payloadInputResolver, debugSupport);
            VerifyOrchestrator orchestrator = new VerifyOrchestrator(cryptoService, dssService, debugSupport);

            orchestrator.execute(request, content);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    private VerifyRequest buildRequest() {
        return new VerifyRequest(
                mode,
                alg,
                inFile,
                pubDir,
                pubFile,
                detached,
                payloadFile,
                payloadHashFile,
                canonicalizePayload,
                truststorePath,
                truststoreType,
                truststorePassword,
                validationPolicyFile,
                debug
        );
    }
}