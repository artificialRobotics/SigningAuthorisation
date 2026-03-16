package artificialrobotics.com.SigningAuthorisation.verify;

import eu.europa.esig.dss.validation.reports.Reports;

public final class VerifyOrchestrator {

    private final VerifyCryptoService cryptoService;
    private final VerifyDssService dssService;
    private final VerifyDebugSupport debugSupport;

    public VerifyOrchestrator(VerifyCryptoService cryptoService,
                              VerifyDssService dssService,
                              VerifyDebugSupport debugSupport) {
        this.cryptoService = cryptoService;
        this.dssService = dssService;
        this.debugSupport = debugSupport;
    }

    public void execute(VerifyRequest request, String content) throws Exception {
        debugSupport.debug("mode", request.getMode());
        debugSupport.debug("input file", String.valueOf(request.getInFile().toAbsolutePath()));
        debugSupport.debug("input length", String.valueOf(content.length()));

        switch (request.getMode().toLowerCase()) {
            case "crypto" -> executeCrypto(request, content);
            case "eidas" -> executeEidas(request, content);
            case "mixed" -> executeMixed(request, content);
            default -> throw new IllegalArgumentException("Unsupported --mode: " + request.getMode());
        }
    }

    private void executeCrypto(VerifyRequest request, String content) throws Exception {
        boolean cryptoOk = cryptoService.verifyCrypto(content, request);
        System.out.println("VALID (crypto-only): " + cryptoOk);
        System.out.println(cryptoOk ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
    }

    private void executeEidas(VerifyRequest request, String content) throws Exception {
        dssService.verifyWithDss(content, request);
    }

    private void executeMixed(VerifyRequest request, String content) throws Exception {
        if (!request.hasTruststore()) {
            throw new IllegalArgumentException("--truststore is required for --mode mixed.");
        }
        if (!request.hasTruststorePassword()) {
            throw new IllegalArgumentException("--truststorePassword is required for --mode mixed.");
        }
        if (!request.hasPublicKeyMaterial()) {
            throw new IllegalArgumentException("mixed mode requires --pub-dir and --pub-file for the crypto part.");
        }

        debugSupport.debug("mixed", "starting crypto part");
        boolean cryptoOk = cryptoService.verifyCrypto(content, request);
        System.out.println("MIXED CRYPTO RESULT: " + (cryptoOk ? "OK" : "NOT OK"));

        boolean certOk;
        if (request.hasPayloadFile()) {
            debugSupport.debug("mixed", "payload present -> using document-based DSS certificate derivation");
            Reports documentReports = dssService.buildDssDocumentReports(content, request, true);
            certOk = dssService.deriveMixedDssCertificateResult(documentReports, content, request);
        } else {
            debugSupport.debug("mixed", "payload absent -> using certificate-only DSS fallback directly");
            System.out.println("INFO: Mixed mode with --payloadHashFile and without --payload skips document-based DSS signature analysis.");
            certOk = dssService.verifyCertificateOnlyWithDss(
                    dssService.extractLeafCertificateFromInput(content),
                    request
            );
        }

        System.out.println("MIXED DSS CERT RESULT: " + (certOk ? "OK" : "NOT OK"));

        boolean finalOk = cryptoOk && certOk;
        System.out.println(finalOk ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
    }
}