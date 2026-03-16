package artificialrobotics.com.SigningAuthorisation.verify;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import artificialrobotics.com.SigningAuthorisation.jose.JoseInputParser;
import artificialrobotics.com.SigningAuthorisation.cli.PayloadInputData;
import artificialrobotics.com.SigningAuthorisation.cli.PayloadInputResolver;

public final class VerifyDssService {

    private final PayloadInputResolver payloadInputResolver;
    private final VerifyDebugSupport debugSupport;

    public VerifyDssService(PayloadInputResolver payloadInputResolver, VerifyDebugSupport debugSupport) {
        this.payloadInputResolver = payloadInputResolver;
        this.debugSupport = debugSupport;
    }

    public void verifyWithDss(String content, VerifyRequest request) throws Exception {
        if (!request.hasTruststore()) {
            throw new IllegalArgumentException("--truststore is required for --mode eidas.");
        }
        if (!request.hasTruststorePassword()) {
            throw new IllegalArgumentException("--truststorePassword is required for --mode eidas.");
        }

        if (request.getPubDir() != null || request.getPubFile() != null) {
            System.out.println("INFO: --pub-dir / --pub-file are ignored in DSS/eIDAS mode. DSS uses truststore + validation policy.");
        }

        Reports reports = buildDssDocumentReports(content, request, true);

        System.out.println("Validation process finished.");
        System.out.println("Simple report object available: " + (reports.getSimpleReport() != null));
        System.out.println("Detailed report object available: " + (reports.getDetailedReport() != null));
        System.out.println("Diagnostic data available: " + (reports.getDiagnosticData() != null));

        printDssResultSummary(reports);

        boolean overallValid = isDssValidationSuccessful(reports);
        System.out.println(overallValid ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
    }

    public boolean deriveMixedDssCertificateResult(Reports reports,
                                                   String content,
                                                   VerifyRequest request) throws Exception {
        TriState docBased = deriveDocumentBasedCertificateTriState(reports);
        debugSupport.debug("mixed document-based cert tristate", String.valueOf(docBased));

        if (docBased != TriState.UNKNOWN) {
            return docBased == TriState.TRUE;
        }

        System.out.println("INFO: Mixed DSS document-based certificate result is UNKNOWN. Falling back to focused DSS certificate validation.");

        X509Certificate signingCert = extractLeafCertificateFromInput(content);
        return verifyCertificateOnlyWithDss(signingCert, request);
    }

    public Reports buildDssDocumentReports(String content,
                                           VerifyRequest request,
                                           boolean printPolicyInfo) throws Exception {

        String jsonForDss = JoseInputParser.toJoseJsonForDss(content);

        debugSupport.debug("dss jose json length", String.valueOf(jsonForDss.length()));
        debugSupport.debugMultiline("dss jose json", jsonForDss);

        DSSDocument sigDoc = new InMemoryDocument(
                jsonForDss.getBytes(StandardCharsets.UTF_8),
                "sig.jws",
                MimeTypeEnum.JOSE_JSON
        );

        CommonCertificateVerifier verifier = buildCertificateVerifierFromTruststore(request);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(sigDoc);
        validator.setCertificateVerifier(verifier);

        if (request.getPayloadFile() != null) {
            PayloadInputData payloadData = payloadInputResolver.loadDetachedPayload(
                    request.getPayloadFile(),
                    request.getCanonicalizePayload()
            );
            byte[] raw = payloadData.getBytes();

            validator.setDetachedContents(List.of(new InMemoryDocument(raw)));
            System.out.println("INFO: DSS detached content loaded from --payload.");
            debugSupport.debugPayload(raw, "dss detached payload");
            debugSupport.debugRawPayloadStructure(raw, "dss detached payload");
            String protectedStr = JoseInputParser.extractProtectedHeaderJson(content);
            debugSupport.debugSigDHashComparisons(protectedStr, raw, "dss detached payload");
        } else {
            System.out.println("INFO: No detached payload provided to DSS.");
        }

        Reports reports;
        if (request.getValidationPolicyFile() != null) {
            if (!Files.exists(request.getValidationPolicyFile())) {
                throw new IllegalArgumentException("Validation policy file not found: " + request.getValidationPolicyFile());
            }
            reports = validator.validateDocument(request.getValidationPolicyFile().toFile());
            if (printPolicyInfo) {
                System.out.println("Using custom validation policy: " + request.getValidationPolicyFile().toAbsolutePath());
            }
        } else {
            reports = validator.validateDocument((File) null);
            if (printPolicyInfo) {
                System.out.println("Using DSS default validation policy.");
            }
        }

        return reports;
    }

    public X509Certificate extractLeafCertificateFromInput(String content) throws Exception {
        String protectedJson = JoseInputParser.extractProtectedHeaderJson(content);
        String leafCertDerB64 = JoseInputParser.extractFirstStringFromJsonArray(protectedJson, "\"x5c\"");
        if (leafCertDerB64 == null) {
            throw new IllegalArgumentException("Missing x5c[0] in protected header. Mixed mode DSS certificate validation requires x5c.");
        }

        byte[] certDer = Base64.getDecoder().decode(leafCertDerB64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

        debugSupport.debug("leaf cert subject", cert.getSubjectX500Principal().getName());
        debugSupport.debug("leaf cert issuer", cert.getIssuerX500Principal().getName());
        debugSupport.debug("leaf cert serial", cert.getSerialNumber().toString(16));
        return cert;
    }

    public boolean verifyCertificateOnlyWithDss(X509Certificate signingCert,
                                                VerifyRequest request) throws Exception {

        CertificateToken token = new CertificateToken(signingCert);

        CommonCertificateVerifier verifier = buildCertificateVerifierFromTruststore(request);

        CertificateValidator validator = CertificateValidator.fromCertificate(token);
        validator.setCertificateVerifier(verifier);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA);

        CertificateReports reports = validator.validate();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        DetailedReport detailedReport = reports.getDetailedReport();
        SimpleCertificateReport simpleReport = reports.getSimpleReport();

        System.out.println("MIXED DSS CERT FALLBACK finished.");
        System.out.println("Certificate diagnostic data available: " + (diagnosticData != null));
        System.out.println("Certificate detailed report available: " + (detailedReport != null));
        System.out.println("Certificate simple report available: " + (simpleReport != null));

        Boolean reflected = invokeBooleanNoArg(simpleReport, "isValid");
        debugSupport.debug("mixed cert fallback reflected isValid()", String.valueOf(reflected));
        if (Boolean.TRUE.equals(reflected)) {
            return true;
        }

        String detailedText = detailedReport != null ? String.valueOf(detailedReport) : null;
        String indication = firstGroup(detailedText, "(?s)<Indication>(.*?)</Indication>");
        String subIndication = firstGroup(detailedText, "(?s)<SubIndication>(.*?)</SubIndication>");

        if (indication != null) {
            System.out.println("MIXED DSS CERT FALLBACK INDICATION: " + indication);
        }
        if (subIndication != null) {
            System.out.println("MIXED DSS CERT FALLBACK SUB-INDICATION: " + subIndication);
        }

        String upperInd = upper(indication);
        String upperSub = upper(subIndication);

        if ("TOTAL_PASSED".equals(upperInd) || "PASSED".equals(upperInd)) {
            return true;
        }

        if (containsAny(upperSub,
                "NO_CERTIFICATE_CHAIN_FOUND",
                "CERTIFICATE_CHAIN_GENERAL_FAILURE",
                "REVOKED",
                "EXPIRED",
                "NOT_YET_VALID",
                "OUT_OF_BOUNDS_NO_POE",
                "OUT_OF_BOUNDS_NOT_REVOKED",
                "TRY_LATER",
                "REVOCATION_OUT_OF_BOUNDS_NO_POE",
                "REVOCATION_OUT_OF_BOUNDS_NOT_REVOKED",
                "CHAIN_CONSTRAINTS_FAILURE")) {
            return false;
        }

        if (Boolean.FALSE.equals(reflected)) {
            return false;
        }

        System.out.println("INFO: No negative DSS certificate/trust indication detected in fallback. Treating certificate check as OK.");
        return true;
    }

    private TriState deriveDocumentBasedCertificateTriState(Reports reports) {
        if (reports == null || reports.getSimpleReport() == null) {
            return TriState.UNKNOWN;
        }

        List<String> ids = extractSignatureIdsFromSimpleReport(reports);
        if (ids.isEmpty()) {
            return TriState.UNKNOWN;
        }

        String detailedXml = safeToString(reports.getDetailedReport());
        Object simpleReport = reports.getSimpleReport();

        TriState certAll = TriState.TRUE;

        for (String id : ids) {
            DssIndicationInfo info = extractDetailedIndicationInfo(detailedXml, id);
            TriState cert = classifyCert(info);

            if (cert == TriState.UNKNOWN) {
                cert = firstKnownTriState(simpleReport, id,
                        "isSigningCertificateValid",
                        "isSigningCertificateTrusted",
                        "isCertificateValid",
                        "isTrustAnchorValid",
                        "isTrustChainValid");
            }

            if (cert == TriState.UNKNOWN) {
                String indication = info.indication;
                if (indication == null) {
                    indication = invokeStringMethod(simpleReport, "getIndication", id);
                }
                String upperInd = upper(indication);
                if ("TOTAL_PASSED".equals(upperInd) || "PASSED".equals(upperInd)) {
                    cert = TriState.TRUE;
                }
            }

            debugSupport.debug("mixed signature id", id);
            debugSupport.debug("mixed cert tristate for signature", String.valueOf(cert));

            certAll = mergeTriStateAnd(certAll, cert);
        }

        return certAll;
    }

    private CommonCertificateVerifier buildCertificateVerifierFromTruststore(VerifyRequest request) throws Exception {
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

        debugSupport.debug("truststore path", String.valueOf(request.getTruststorePath().toAbsolutePath()));
        debugSupport.debug("truststore type", request.getTruststoreType());
        debugSupport.debug("truststore trusted certificates loaded", String.valueOf(trustedCount));

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trustedSource);
        return verifier;
    }

    private static void printDssResultSummary(Reports reports) {
        List<String> ids = extractSignatureIdsFromSimpleReport(reports);
        if (ids.isEmpty()) {
            System.out.println("DSS OVERALL : NOT OK (no signatures found)");
            System.out.println("DSS CRYPTO  : UNKNOWN");
            System.out.println("DSS CERT    : UNKNOWN");
            System.out.println("DSS PROFILE : UNKNOWN");
            return;
        }

        String detailedXml = safeToString(reports != null ? reports.getDetailedReport() : null);

        boolean overallAllOk = true;
        TriState cryptoAll = TriState.TRUE;
        TriState certAll = TriState.TRUE;
        TriState profileAll = TriState.TRUE;

        Object simpleReport = reports.getSimpleReport();

        for (String id : ids) {
            boolean overall = invokeBooleanMethod(simpleReport, "isValid", id, false);

            DssIndicationInfo info = extractDetailedIndicationInfo(detailedXml, id);

            TriState crypto = classifyCrypto(info);
            TriState cert = classifyCert(info);
            TriState profile = classifyProfile(info);

            overallAllOk &= overall;
            cryptoAll = mergeTriStateAnd(cryptoAll, crypto);
            certAll = mergeTriStateAnd(certAll, cert);
            profileAll = mergeTriStateAnd(profileAll, profile);

            String indication = info.indication;
            String subIndication = info.subIndication;

            if (indication == null) {
                indication = invokeStringMethod(simpleReport, "getIndication", id);
            }
            if (subIndication == null) {
                subIndication = invokeStringMethod(simpleReport, "getSubIndication", id);
            }

            System.out.println("DSS SIGNATURE ID: " + id);
            System.out.println("  OVERALL : " + (overall ? "OK" : "NOT OK"));
            System.out.println("  CRYPTO  : " + triStateToText(crypto));
            System.out.println("  CERT    : " + triStateToText(cert));
            System.out.println("  PROFILE : " + triStateToText(profile));
            if (indication != null) {
                System.out.println("  INDICATION     : " + indication);
            }
            if (subIndication != null) {
                System.out.println("  SUB-INDICATION : " + subIndication);
            }
        }

        System.out.println("DSS OVERALL : " + (overallAllOk ? "OK" : "NOT OK"));
        System.out.println("DSS CRYPTO  : " + triStateToText(cryptoAll));
        System.out.println("DSS CERT    : " + triStateToText(certAll));
        System.out.println("DSS PROFILE : " + triStateToText(profileAll));
    }

    private static boolean isDssValidationSuccessful(Reports reports) {
        List<String> ids = extractSignatureIdsFromSimpleReport(reports);
        if (ids.isEmpty()) {
            return false;
        }

        Object simpleReport = reports.getSimpleReport();
        for (String id : ids) {
            if (!invokeBooleanMethod(simpleReport, "isValid", id, false)) {
                return false;
            }
        }
        return true;
    }

    private enum TriState {
        TRUE, FALSE, UNKNOWN
    }

    private static final class DssIndicationInfo {
        final String indication;
        final String subIndication;

        DssIndicationInfo(String indication, String subIndication) {
            this.indication = indication;
            this.subIndication = subIndication;
        }
    }

    private static DssIndicationInfo extractDetailedIndicationInfo(String xml, String signatureId) {
        if (xml == null || signatureId == null || signatureId.isBlank()) {
            return new DssIndicationInfo(null, null);
        }

        String quotedId = Pattern.quote(signatureId);

        String indication = firstGroup(xml,
                "(?s)<Signature\\b[^>]*Id\\s*=\\s*\"" + quotedId + "\"[^>]*>.*?<Indication>(.*?)</Indication>",
                "(?s)<Signature\\b[^>]*Id\\s*=\\s*\"" + quotedId + "\"[^>]*>.*?<Conclusion>.*?<Indication>(.*?)</Indication>",
                "(?s)<Signature\\b[^>]*Id\\s*=\\s*\"" + quotedId + "\"[^>]*>.*?<ValidationConclusion>.*?<Indication>(.*?)</Indication>"
        );

        String subIndication = firstGroup(xml,
                "(?s)<Signature\\b[^>]*Id\\s*=\\s*\"" + quotedId + "\"[^>]*>.*?<SubIndication>(.*?)</SubIndication>",
                "(?s)<Signature\\b[^>]*Id\\s*=\\s*\"" + quotedId + "\"[^>]*>.*?<Conclusion>.*?<SubIndication>(.*?)</SubIndication>",
                "(?s)<Signature\\b[^>]*Id\\s*=\\s*\"" + quotedId + "\"[^>]*>.*?<ValidationConclusion>.*?<SubIndication>(.*?)</SubIndication>"
        );

        return new DssIndicationInfo(indication, subIndication);
    }

    private static List<String> extractSignatureIdsFromSimpleReport(Reports reports) {
        List<String> ids = new ArrayList<>();
        if (reports == null || reports.getSimpleReport() == null) {
            return ids;
        }

        Object simpleReport = reports.getSimpleReport();

        try {
            Method getSignatureIdList = simpleReport.getClass().getMethod("getSignatureIdList");
            Object idsObj = getSignatureIdList.invoke(simpleReport);
            if (idsObj instanceof Iterable<?> iterable) {
                for (Object o : iterable) {
                    if (o != null) {
                        ids.add(String.valueOf(o));
                    }
                }
            }
            if (!ids.isEmpty()) {
                return ids;
            }
        } catch (Exception ignored) {
        }

        try {
            Method getFirstSignatureId = simpleReport.getClass().getMethod("getFirstSignatureId");
            Object firstId = getFirstSignatureId.invoke(simpleReport);
            if (firstId != null) {
                ids.add(String.valueOf(firstId));
            }
        } catch (Exception ignored) {
        }

        return ids;
    }

    private static TriState classifyCrypto(DssIndicationInfo info) {
        if (info == null) return TriState.UNKNOWN;
        String ind = upper(info.indication);
        String sub = upper(info.subIndication);

        if ("TOTAL_PASSED".equals(ind) || "PASSED".equals(ind)) return TriState.TRUE;

        if (containsAny(sub,
                "HASH_FAILURE",
                "SIG_CRYPTO_FAILURE",
                "CRYPTO_CONSTRAINTS_FAILURE",
                "SIG_CONSTRAINTS_FAILURE",
                "FORMAT_FAILURE",
                "SIGNED_DATA_NOT_FOUND")) {
            return TriState.FALSE;
        }

        if ("FAILED".equals(ind) && containsAny(sub,
                "SIG_CRYPTO_FAILURE",
                "HASH_FAILURE",
                "CRYPTO_CONSTRAINTS_FAILURE",
                "SIG_CONSTRAINTS_FAILURE")) {
            return TriState.FALSE;
        }

        return TriState.UNKNOWN;
    }

    private static TriState classifyCert(DssIndicationInfo info) {
        if (info == null) return TriState.UNKNOWN;
        String ind = upper(info.indication);
        String sub = upper(info.subIndication);

        if ("TOTAL_PASSED".equals(ind) || "PASSED".equals(ind)) return TriState.TRUE;

        if (containsAny(sub,
                "NO_CERTIFICATE_CHAIN_FOUND",
                "CERTIFICATE_CHAIN_GENERAL_FAILURE",
                "REVOKED",
                "EXPIRED",
                "NOT_YET_VALID",
                "OUT_OF_BOUNDS_NO_POE",
                "OUT_OF_BOUNDS_NOT_REVOKED",
                "TRY_LATER",
                "REVOCATION_OUT_OF_BOUNDS_NO_POE",
                "REVOCATION_OUT_OF_BOUNDS_NOT_REVOKED",
                "CHAIN_CONSTRAINTS_FAILURE")) {
            return TriState.FALSE;
        }

        if ("INDETERMINATE".equals(ind) && containsAny(sub,
                "TRY_LATER",
                "NO_CERTIFICATE_CHAIN_FOUND",
                "OUT_OF_BOUNDS_NO_POE",
                "OUT_OF_BOUNDS_NOT_REVOKED")) {
            return TriState.FALSE;
        }

        return TriState.UNKNOWN;
    }

    private static TriState classifyProfile(DssIndicationInfo info) {
        if (info == null) return TriState.UNKNOWN;
        String ind = upper(info.indication);
        String sub = upper(info.subIndication);

        if ("TOTAL_PASSED".equals(ind) || "PASSED".equals(ind)) return TriState.TRUE;

        if (containsAny(sub,
                "FORMAT_FAILURE",
                "SIG_CONSTRAINTS_FAILURE",
                "CHAIN_CONSTRAINTS_FAILURE",
                "CRYPTO_CONSTRAINTS_FAILURE",
                "NO_SIGNING_CERTIFICATE_FOUND")) {
            return TriState.FALSE;
        }

        if ("FAILED".equals(ind) && containsAny(sub,
                "FORMAT_FAILURE",
                "SIG_CONSTRAINTS_FAILURE",
                "CHAIN_CONSTRAINTS_FAILURE")) {
            return TriState.FALSE;
        }

        return TriState.UNKNOWN;
    }

    private static TriState firstKnownTriState(Object target, String signatureId, String... methodNames) {
        if (target == null) return TriState.UNKNOWN;

        for (String methodName : methodNames) {
            try {
                Method m = target.getClass().getMethod(methodName, String.class);
                Object result = m.invoke(target, signatureId);
                if (result instanceof Boolean b) {
                    return b ? TriState.TRUE : TriState.FALSE;
                }
            } catch (Exception ignored) {
            }
        }

        return TriState.UNKNOWN;
    }

    private static TriState mergeTriStateAnd(TriState a, TriState b) {
        if (a == TriState.FALSE || b == TriState.FALSE) return TriState.FALSE;
        if (a == TriState.UNKNOWN || b == TriState.UNKNOWN) return TriState.UNKNOWN;
        return TriState.TRUE;
    }

    private static String triStateToText(TriState t) {
        return switch (t) {
            case TRUE -> "OK";
            case FALSE -> "NOT OK";
            case UNKNOWN -> "UNKNOWN";
        };
    }

    private static String safeToString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static String upper(String s) {
        return s == null ? null : s.toUpperCase();
    }

    private static boolean containsAny(String s, String... needles) {
        if (s == null) return false;
        for (String n : needles) {
            if (s.contains(n)) return true;
        }
        return false;
    }

    private static String firstGroup(String input, String... regexes) {
        if (input == null) return null;
        for (String regex : regexes) {
            Matcher m = Pattern.compile(regex).matcher(input);
            if (m.find()) return m.group(1);
        }
        return null;
    }

    private static Boolean invokeBooleanNoArg(Object target, String methodName) {
        if (target == null) return null;
        try {
            Method m = target.getClass().getMethod(methodName);
            Object result = m.invoke(target);
            return (result instanceof Boolean b) ? b : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean invokeBooleanMethod(Object target, String methodName, String signatureId, boolean fallback) {
        if (target == null) return fallback;
        try {
            Method m = target.getClass().getMethod(methodName, String.class);
            Object result = m.invoke(target, signatureId);
            return (result instanceof Boolean b) ? b : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    private static String invokeStringMethod(Object target, String methodName, String signatureId) {
        if (target == null) return null;
        try {
            Method m = target.getClass().getMethod(methodName, String.class);
            Object result = m.invoke(target, signatureId);
            return result != null ? String.valueOf(result) : null;
        } catch (Exception e) {
            return null;
        }
    }
}