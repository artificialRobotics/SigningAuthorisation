package artificialrobotics.com.SigningAuthorisation.xades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public final class XadesVerifyService {

    public void verify(XadesVerifyRequest request) throws Exception {
        request.validate();

        Reports reports = buildReports(request);

        System.out.println("Validation process finished.");
        System.out.println("Simple report object available: " + (reports.getSimpleReport() != null));
        System.out.println("Detailed report object available: " + (reports.getDetailedReport() != null));
        System.out.println("Diagnostic data available: " + (reports.getDiagnosticData() != null));

        printSummary(reports);

        boolean overallValid = isOverallValidXades(reports);
        System.out.println(overallValid ? "FINAL RESULT: XAdES IS VALID" : "FINAL RESULT: XAdES IS NOT VALID");

        if (!overallValid) {
            throw new IllegalStateException("XAdES validation failed.");
        }
    }

    public Reports buildReports(XadesVerifyRequest request) throws Exception {
        byte[] signatureBytes = Files.readAllBytes(request.getSignatureFile());
        byte[] payloadBytes = Files.readAllBytes(request.getPayloadFile());

        debug(request, "signature", request.getSignatureFile().toAbsolutePath().toString());
        debug(request, "payload", request.getPayloadFile().toAbsolutePath().toString());
        debug(request, "truststore", request.getTruststorePath().toAbsolutePath().toString());
        debug(request, "signature length", String.valueOf(signatureBytes.length));
        debug(request, "payload length", String.valueOf(payloadBytes.length));

        DSSDocument signatureDocument = new InMemoryDocument(
            signatureBytes,
            request.getSignatureFile().getFileName().toString(),
            MimeTypeEnum.XML
        );

        DSSDocument detachedPayload = new InMemoryDocument(
            payloadBytes,
            request.getPayloadFile().getFileName().toString(),
            MimeTypeEnum.XML
        );

        CommonCertificateVerifier verifier = buildCertificateVerifierFromTruststore(request);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureDocument);
        validator.setCertificateVerifier(verifier);
        validator.setDetachedContents(List.of(detachedPayload));

        debug(request, "validator class", validator.getClass().getName());
        debug(request, "detached contents count", "1");

        Reports reports;
        if (request.getValidationPolicyFile() != null) {
            reports = validator.validateDocument(request.getValidationPolicyFile().toFile());
            System.out.println("Using custom validation policy: " + request.getValidationPolicyFile().toAbsolutePath());
        } else {
            reports = validator.validateDocument();
            System.out.println("Using DSS default validation policy.");
        }

        return reports;
    }

    private CommonCertificateVerifier buildCertificateVerifierFromTruststore(XadesVerifyRequest request) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(request.getTruststoreType());
        try (InputStream is = Files.newInputStream(request.getTruststorePath())) {
            trustStore.load(is, request.getTruststorePassword().toCharArray());
        }

        CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();
        Enumeration<String> aliases = trustStore.aliases();
        int trustedCount = 0;

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            java.security.cert.Certificate cert = trustStore.getCertificate(alias);
            if (cert instanceof X509Certificate x509) {
                trustedSource.addCertificate(new CertificateToken(x509));
                trustedCount++;
            }
        }

        debug(request, "truststore type", request.getTruststoreType());
        debug(request, "truststore trusted certificates loaded", String.valueOf(trustedCount));

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trustedSource);
        return verifier;
    }

    private void printSummary(Reports reports) {
        SimpleReport simpleReport = reports.getSimpleReport();
        if (simpleReport == null) {
            System.out.println("DSS OVERALL : NOT OK (no simple report)");
            return;
        }

        List<String> signatureIds = new ArrayList<>(simpleReport.getSignatureIdList());
        if (signatureIds.isEmpty()) {
            System.out.println("DSS OVERALL : NOT OK (no signatures found)");
            return;
        }

        boolean allValid = true;
        boolean allXades = true;

        for (String signatureId : signatureIds) {
            boolean valid = simpleReport.isValid(signatureId);
            Indication indication = simpleReport.getIndication(signatureId);
            SubIndication subIndication = simpleReport.getSubIndication(signatureId);
            SignatureLevel format = simpleReport.getSignatureFormat(signatureId);
            String signedBy = simpleReport.getSignedBy(signatureId);

            boolean isXades = format != null && format.name().toUpperCase().startsWith("XADES");

            allValid &= valid;
            allXades &= isXades;

            System.out.println("DSS SIGNATURE ID: " + signatureId);
            System.out.println("  OVERALL        : " + (valid ? "OK" : "NOT OK"));
            System.out.println("  SIGNED BY      : " + (signedBy != null ? signedBy : "n/a"));
            System.out.println("  FORMAT         : " + (format != null ? format.name() : "n/a"));
            System.out.println("  XADES FORMAT   : " + (isXades ? "YES" : "NO"));
            System.out.println("  INDICATION     : " + (indication != null ? indication.name() : "n/a"));
            System.out.println("  SUB-INDICATION : " + (subIndication != null ? subIndication.name() : "n/a"));
        }

        System.out.println("DSS OVERALL       : " + (allValid ? "OK" : "NOT OK"));
        System.out.println("DSS XAdES FORMAT  : " + (allXades ? "YES" : "NO"));
        System.out.println("DSS SIGNATURES    : " + signatureIds.size());
        System.out.println("DSS VALID         : " + simpleReport.getValidSignaturesCount() + "/" + simpleReport.getSignaturesCount());
    }

    private boolean isOverallValidXades(Reports reports) {
        SimpleReport simpleReport = reports.getSimpleReport();
        if (simpleReport == null) {
            return false;
        }

        List<String> signatureIds = simpleReport.getSignatureIdList();
        if (signatureIds == null || signatureIds.isEmpty()) {
            return false;
        }

        for (String signatureId : signatureIds) {
            if (!simpleReport.isValid(signatureId)) {
                return false;
            }

            SignatureLevel format = simpleReport.getSignatureFormat(signatureId);
            if (format == null || !format.name().toUpperCase().startsWith("XADES")) {
                return false;
            }
        }

        return true;
    }

    private void debug(XadesVerifyRequest request, String label, String value) {
        if (request.isDebug()) {
            System.out.println("[XADES-VERIFY-DEBUG] " + label + ": " + value);
        }
    }
}