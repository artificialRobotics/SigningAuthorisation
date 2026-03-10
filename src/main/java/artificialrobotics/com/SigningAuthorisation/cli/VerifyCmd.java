package artificialrobotics.com.SigningAuthorisation.cli;

import artificialrobotics.com.SigningAuthorisation.InitBC;
import artificialrobotics.com.SigningAuthorisation.certificates.PEMCertificateLoader;
import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;
import artificialrobotics.com.SigningAuthorisation.signingKeys.PublicKeyFactory;

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

import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@CommandLine.Command(name = "verify", description = "Verify JWS/JAdES (crypto-only, eIDAS/DSS, or mixed).")
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

    @CommandLine.Option(names = "--detached", description = "Treat input as detached JWS. Provide --payload for verification.")
    boolean detached;

    @CommandLine.Option(names = "--payload", description = "Detached payload file (raw bytes).")
    Path payloadFile;

    @CommandLine.Option(
            names = "--payloadHashFile",
            description = "Crypto or mixed mode only: File containing the Base64/Base64URL encoded hash value over the signing input. Used as alternative to --payload."
    )
    Path payloadHashFile;

    @CommandLine.Option(names = "--canonicalize-payload", description = "Apply canonicalization to detached payload before verification. Supported value: jcs")
    String canonicalizePayload;

    @CommandLine.Option(names = "--truststore", description = "Truststore file for DSS verification (PKCS12/JKS).")
    Path truststorePath;

    @CommandLine.Option(names = "--truststoreType", description = "Truststore type: PKCS12 | JKS (default: PKCS12)")
    String truststoreType = "PKCS12";

    @CommandLine.Option(names = "--truststorePassword", description = "Truststore password for DSS verification.")
    String truststorePassword;

    @CommandLine.Option(names = "--validationPolicy", description = "Custom DSS validation policy XML file. If omitted, DSS default policy is used.")
    Path validationPolicyFile;

    @CommandLine.Option(names = "--debug", description = "Print additional debug information.")
    boolean debug;

    @Override
    public void run() {
        try {
            new InitBC();

            final String content = Files.readString(inFile, StandardCharsets.UTF_8).trim();
            debug("mode", mode);
            debug("input file", String.valueOf(inFile.toAbsolutePath()));
            debug("input length", String.valueOf(content.length()));

            switch (mode.toLowerCase()) {
                case "crypto" -> {
                    boolean cryptoOk = verifyCrypto(content);
                    System.out.println("VALID (crypto-only): " + cryptoOk);
                    System.out.println(cryptoOk ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
                }
                case "eidas" -> verifyWithDss(content);
                case "mixed" -> verifyMixed(content);
                default -> throw new IllegalArgumentException("Unsupported --mode: " + mode);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    /* ====================== MIXED MODE ====================== */

    private void verifyMixed(String content) throws Exception {
        if (truststorePath == null) {
            throw new IllegalArgumentException("--truststore is required for --mode mixed.");
        }
        if (truststorePassword == null) {
            throw new IllegalArgumentException("--truststorePassword is required for --mode mixed.");
        }
        if (pubDir == null || pubFile == null) {
            throw new IllegalArgumentException("mixed mode requires --pub-dir and --pub-file for the crypto part.");
        }

        debug("mixed", "starting crypto part");
        boolean cryptoOk = verifyCrypto(content);
        System.out.println("MIXED CRYPTO RESULT: " + (cryptoOk ? "OK" : "NOT OK"));

        boolean certOk;
        if (payloadFile != null) {
            debug("mixed", "payload present -> using document-based DSS certificate derivation");
            Reports documentReports = buildDssDocumentReports(content, true);
            certOk = deriveMixedDssCertificateResult(documentReports, content);
        } else {
            debug("mixed", "payload absent -> using certificate-only DSS fallback directly");
            System.out.println("INFO: Mixed mode with --payloadHashFile and without --payload skips document-based DSS signature analysis.");
            X509Certificate signingCert = extractLeafCertificateFromInput(content);
            certOk = verifyCertificateOnlyWithDss(signingCert);
        }

        System.out.println("MIXED DSS CERT RESULT: " + (certOk ? "OK" : "NOT OK"));

        boolean finalOk = cryptoOk && certOk;
        System.out.println(finalOk ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
    }

    private boolean deriveMixedDssCertificateResult(Reports reports, String content) throws Exception {
        TriState docBased = deriveDocumentBasedCertificateTriState(reports);
        debug("mixed document-based cert tristate", String.valueOf(docBased));

        if (docBased != TriState.UNKNOWN) {
            return docBased == TriState.TRUE;
        }

        System.out.println("INFO: Mixed DSS document-based certificate result is UNKNOWN. Falling back to focused DSS certificate validation.");

        X509Certificate signingCert = extractLeafCertificateFromInput(content);
        return verifyCertificateOnlyWithDss(signingCert);
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

            debug("mixed signature id", id);
            debug("mixed cert tristate for signature", String.valueOf(cert));
            certAll = mergeTriStateAnd(certAll, cert);
        }

        return certAll;
    }

    private boolean verifyCertificateOnlyWithDss(X509Certificate signingCert) throws Exception {
        CertificateToken token = new CertificateToken(signingCert);

        CommonCertificateVerifier verifier = buildCertificateVerifierFromTruststore();

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
        debug("mixed cert fallback reflected isValid()", String.valueOf(reflected));
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

    /* ====================== CRYPTO MODE ====================== */

    private boolean verifyCrypto(String content) throws Exception {
        if (payloadFile != null && payloadHashFile != null) {
            throw new IllegalArgumentException("In crypto or mixed mode, use either --payload OR --payloadHashFile, not both.");
        }

        String protectedB64;
        String payloadB64 = null;
        String signatureB64;

        if (isJsonSerialization(content)) {
            protectedB64 = extractJsonValue(content, "\"protected\"");
            signatureB64 = extractJsonValue(content, "\"signature\"");
            if (content.contains("\"payload\"")) {
                payloadB64 = extractJsonValue(content, "\"payload\"");
            }
        } else {
            String[] parts = content.split("\\.", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
            }
            protectedB64 = parts[0];
            payloadB64 = parts[1];
            signatureB64 = parts[2];
        }

        byte[] protectedJson = Base64.getUrlDecoder().decode(protectedB64);
        String protectedStr = new String(protectedJson, StandardCharsets.UTF_8);
        boolean b64false = protectedStr.contains("\"b64\":false");

        String resolvedAlg = alg;
        if ("ph".equalsIgnoreCase(alg)) {
            String headerAlg = extractJsonValue(protectedStr, "\"alg\"");
            if (headerAlg == null || headerAlg.isEmpty()) {
                throw new IllegalArgumentException("Protected header does not contain an 'alg' claim.");
            }
            resolvedAlg = headerAlg;
        }

        byte[] sig = Base64.getUrlDecoder().decode(signatureB64);

        debug("crypto alg (requested)", alg);
        debug("crypto alg (resolved)", resolvedAlg);
        debug("crypto detached", String.valueOf(detached));
        debug("crypto b64=false", String.valueOf(b64false));
        debug("crypto protected.b64url", protectedB64);
        debugMultiline("crypto protected.json", protectedStr);
        debug("crypto signature bytes", String.valueOf(sig.length));
        debug("crypto signature b64url prefix", abbreviate(signatureB64, 120));

        PublicKey pub;
        try {
            pub = PublicKeyFactory.load(pubDir, pubFile);
        } catch (Exception e) {
            var cl = new PEMCertificateLoader(pubDir, pubFile);
            cl.load();
            if (cl.getCertificate() == null) {
                throw new IllegalArgumentException("Could not load a public key (neither key nor certificate).", e);
            }
            pub = cl.getCertificate().getPublicKey();
        }

        debug("crypto public key algorithm", pub.getAlgorithm());

        if (payloadHashFile != null) {
            byte[] providedDigest = loadPayloadHashFromFile(payloadHashFile, resolvedAlg);
            debug("crypto mode detail", "using --payloadHashFile");
            debug("crypto provided digest bytes", String.valueOf(providedDigest.length));
            debug("crypto provided digest b64", Base64.getEncoder().encodeToString(providedDigest));
            return verifyJwsUsingProvidedDigest(providedDigest, sig, pub, resolvedAlg);
        }

        byte[] signingInput;
        if (b64false) {
            if (payloadFile == null) {
                throw new IllegalArgumentException("b64=false requires --payload with RAW payload bytes.");
            }
            byte[] left = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
            byte[] raw = loadDetachedPayloadPossiblyCanonicalized();
            debugPayload(raw, "crypto raw payload");
            signingInput = concat(left, raw);
        } else {
            if (detached) {
                if (payloadFile == null) {
                    throw new IllegalArgumentException("detached requires --payload (for b64=true).");
                }
                byte[] raw = loadDetachedPayloadPossiblyCanonicalized();
                debugPayload(raw, "crypto detached payload");
                payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            } else {
                if (payloadB64 == null) {
                    throw new IllegalArgumentException("Embedded signature expects a 'payload' in the JWS.");
                }
                debug("crypto embedded payload b64url", abbreviate(payloadB64, 160));
            }
            signingInput = (protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            debug("crypto payloadB64", abbreviate(payloadB64, 160));
        }

        debug("crypto signingInput bytes", String.valueOf(signingInput.length));
        debug("crypto signingInput sha512 b64", sha512Base64(signingInput));
        debug("crypto signingInput preview", abbreviate(new String(signingInput, StandardCharsets.US_ASCII), 180));

        return verifyJws(signingInput, sig, pub, resolvedAlg);
    }

    /* ====================== DSS / eIDAS FULL ====================== */

    private void verifyWithDss(String content) throws Exception {
        if (truststorePath == null) {
            throw new IllegalArgumentException("--truststore is required for --mode eidas.");
        }
        if (truststorePassword == null) {
            throw new IllegalArgumentException("--truststorePassword is required for --mode eidas.");
        }

        if (pubDir != null || pubFile != null) {
            System.out.println("INFO: --pub-dir / --pub-file are ignored in DSS/eIDAS mode. DSS uses truststore + validation policy.");
        }

        Reports reports = buildDssDocumentReports(content, true);

        System.out.println("Validation process finished.");
        System.out.println("Simple report object available: " + (reports.getSimpleReport() != null));
        System.out.println("Detailed report object available: " + (reports.getDetailedReport() != null));
        System.out.println("Diagnostic data available: " + (reports.getDiagnosticData() != null));

        printDssResultSummary(reports);

        boolean overallValid = isDssValidationSuccessful(reports);
        System.out.println(overallValid ? "FINAL RESULT: JWS IS VALID" : "FINAL RESULT: JWS IS NOT VALID");
    }

    private Reports buildDssDocumentReports(String content, boolean printPolicyInfo) throws Exception {
        String jsonForDss = toJoseJsonForDss(content);

        debug("dss jose json length", String.valueOf(jsonForDss.length()));
        debugMultiline("dss jose json", jsonForDss);

        DSSDocument sigDoc = new InMemoryDocument(
                jsonForDss.getBytes(StandardCharsets.UTF_8),
                "sig.jws",
                MimeTypeEnum.JOSE_JSON
        );

        CommonCertificateVerifier verifier = buildCertificateVerifierFromTruststore();

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(sigDoc);
        validator.setCertificateVerifier(verifier);

        if (payloadFile != null) {
            byte[] raw = loadDetachedPayloadPossiblyCanonicalized();
            validator.setDetachedContents(List.of(new InMemoryDocument(raw)));
            System.out.println("INFO: DSS detached content loaded from --payload.");
            debugPayload(raw, "dss detached payload");
        } else {
            System.out.println("INFO: No detached payload provided to DSS.");
        }

        Reports reports;
        if (validationPolicyFile != null) {
            if (!Files.exists(validationPolicyFile)) {
                throw new IllegalArgumentException("Validation policy file not found: " + validationPolicyFile);
            }
            reports = validator.validateDocument(validationPolicyFile.toFile());
            if (printPolicyInfo) {
                System.out.println("Using custom validation policy: " + validationPolicyFile.toAbsolutePath());
            }
        } else {
            reports = validator.validateDocument((File) null);
            if (printPolicyInfo) {
                System.out.println("Using DSS default validation policy.");
            }
        }
        return reports;
    }

    /* ====================== DSS verifier / truststore helpers ====================== */

    private CommonCertificateVerifier buildCertificateVerifierFromTruststore() throws Exception {
        KeyStore trustStore = KeyStore.getInstance(truststoreType);
        try (InputStream is = Files.newInputStream(truststorePath)) {
            trustStore.load(is, truststorePassword.toCharArray());
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

        debug("truststore path", String.valueOf(truststorePath.toAbsolutePath()));
        debug("truststore type", truststoreType);
        debug("truststore trusted certificates loaded", String.valueOf(trustedCount));

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trustedSource);
        return verifier;
    }

    private X509Certificate extractLeafCertificateFromInput(String content) throws Exception {
        String protectedB64;

        if (isJsonSerialization(content)) {
            protectedB64 = extractJsonValue(content, "\"protected\"");
        } else {
            String[] parts = content.split("\\.", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid compact JWS (expected 3 parts).");
            }
            protectedB64 = parts[0];
        }

        String protectedJson = new String(Base64.getUrlDecoder().decode(protectedB64), StandardCharsets.UTF_8);
        String leafCertDerB64 = extractFirstStringFromJsonArray(protectedJson, "\"x5c\"");
        if (leafCertDerB64 == null) {
            throw new IllegalArgumentException("Missing x5c[0] in protected header. Mixed mode DSS certificate validation requires x5c.");
        }

        byte[] certDer = Base64.getDecoder().decode(leafCertDerB64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

        debug("leaf cert subject", cert.getSubjectX500Principal().getName());
        debug("leaf cert issuer", cert.getIssuerX500Principal().getName());
        debug("leaf cert serial", cert.getSerialNumber().toString(16));
        return cert;
    }

    /* ====================== DSS report helpers ====================== */

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

    private static List<String> extractSignatureIdsFromSimpleReport(Reports reports) {
        List<String> ids = new ArrayList<>();
        if (reports == null || reports.getSimpleReport() == null) return ids;

        Object simpleReport = reports.getSimpleReport();

        try {
            Method getSignatureIdList = simpleReport.getClass().getMethod("getSignatureIdList");
            Object idsObj = getSignatureIdList.invoke(simpleReport);
            if (idsObj instanceof Iterable<?> iterable) {
                for (Object o : iterable) {
                    if (o != null) ids.add(String.valueOf(o));
                }
            }
            if (!ids.isEmpty()) return ids;
        } catch (Exception ignored) {
        }

        try {
            Method getFirstSignatureId = simpleReport.getClass().getMethod("getFirstSignatureId");
            Object firstId = getFirstSignatureId.invoke(simpleReport);
            if (firstId != null) ids.add(String.valueOf(firstId));
        } catch (Exception ignored) {
        }

        return ids;
    }

    private static boolean isDssValidationSuccessful(Reports reports) {
        List<String> ids = extractSignatureIdsFromSimpleReport(reports);
        if (ids.isEmpty()) return false;

        Object simpleReport = reports.getSimpleReport();
        for (String id : ids) {
            if (!invokeBooleanMethod(simpleReport, "isValid", id, false)) return false;
        }
        return true;
    }

    /* ====================== Crypto verification ====================== */

    private static boolean verifyJwsUsingProvidedDigest(byte[] providedDigest, byte[] sig, PublicKey pub, String alg) throws Exception {
        switch (alg) {
            case "RS512": {
                byte[] digestInfo = wrapSha512DigestInfo(providedDigest);
                Signature v = Signature.getInstance("NONEwithRSA", "BC");
                v.initVerify(pub);
                v.update(digestInfo);
                return v.verify(sig);
            }
            case "PS512": {
                Signature v = Signature.getInstance("RAWRSASSA-PSS", "BC");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"),
                        64, 1);
                v.setParameter(pss);
                v.initVerify(pub);
                v.update(providedDigest);
                return v.verify(sig);
            }
            case "ES256":
            case "ES384":
            case "ES512": {
                int fieldSize = ecdsaFieldSizeBytes(alg);
                boolean looksLikeRawConcat = (sig.length == 2 * fieldSize);
                boolean looksLikeDer = (sig.length > 0 && sig[0] == 0x30);

                Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                v.initVerify(pub);
                v.update(providedDigest);

                if (looksLikeRawConcat) return v.verify(concatToDer(sig, fieldSize));
                if (looksLikeDer) return v.verify(sig);

                throw new IllegalArgumentException("Unsupported ECDSA signature encoding (neither raw R||S nor DER).");
            }
            default:
                throw new IllegalArgumentException("Unsupported alg for --payloadHashFile: " + alg);
        }
    }

    private static boolean verifyJws(byte[] signingInput, byte[] sig, PublicKey pub, String alg) throws Exception {
        switch (alg) {
            case "RS512": {
                Signature v = Signature.getInstance("SHA512withRSA");
                v.initVerify(pub);
                v.update(signingInput);
                return v.verify(sig);
            }
            case "PS512": {
                Signature v = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pss = new PSSParameterSpec(
                        "SHA-512", "MGF1",
                        new java.security.spec.MGF1ParameterSpec("SHA-512"),
                        64, 1);
                v.setParameter(pss);
                v.initVerify(pub);
                v.update(signingInput);
                return v.verify(sig);
            }
            case "ES256":
            case "ES384":
            case "ES512": {
                int fieldSize = ecdsaFieldSizeBytes(alg);
                int expectedRawLen = 2 * fieldSize;

                boolean looksLikeRawConcat = (sig.length == expectedRawLen);
                boolean looksLikeDer = (sig.length > 0 && sig[0] == 0x30);

                if (looksLikeRawConcat) {
                    String jca = switch (alg) {
                        case "ES256" -> "SHA256withECDSA";
                        case "ES384" -> "SHA384withECDSA";
                        default -> "SHA512withECDSA";
                    };
                    Signature v = Signature.getInstance(jca);
                    v.initVerify(pub);
                    v.update(signingInput);
                    return v.verify(concatToDer(sig, fieldSize));
                }

                if (looksLikeDer) {
                    byte[] digest = MessageDigest.getInstance(digestAlgForEsFamily(alg)).digest(signingInput);
                    Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                    v.initVerify(pub);
                    v.update(digest);
                    return v.verify(sig);
                }

                throw new IllegalArgumentException("Unsupported ECDSA signature encoding (neither raw R||S nor DER).");
            }
            default:
                throw new IllegalArgumentException("Unsupported alg: " + alg);
        }
    }

    private static byte[] loadPayloadHashFromFile(Path hashFile, String alg) throws Exception {
        String content = Files.readString(hashFile, StandardCharsets.UTF_8).trim();
        if (content.isEmpty()) {
            throw new IllegalArgumentException("Hash file is empty: " + hashFile);
        }
        byte[] digest = decodeBase64OrBase64Url(content);

        int expectedLen = switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512", "RS512", "PS512" -> 64;
            default -> throw new IllegalArgumentException("Unsupported alg for hash file: " + alg);
        };

        if (digest.length != expectedLen) {
            throw new IllegalArgumentException("Unexpected hash length in --payloadHashFile for " + alg +
                    ". Expected " + expectedLen + " bytes, got " + digest.length + ".");
        }

        return digest;
    }

    private static byte[] decodeBase64OrBase64Url(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            return Base64.getUrlDecoder().decode(value);
        }
    }

    private static String digestAlgForEsFamily(String alg) {
        return switch (alg) {
            case "ES256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            case "ES512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported ES alg: " + alg);
        };
    }

    private static int ecdsaFieldSizeBytes(String alg) {
        return switch (alg) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512" -> 66;
            default -> throw new IllegalArgumentException("Unknown ECDSA alg: " + alg);
        };
    }

    private static byte[] wrapSha512DigestInfo(byte[] digest) {
        if (digest == null || digest.length != 64) {
            throw new IllegalArgumentException("SHA-512 digest must be 64 bytes.");
        }
        byte[] prefix = new byte[] {
                0x30, 0x51,
                0x30, 0x0d,
                0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                0x05, 0x00,
                0x04, 0x40
        };
        byte[] out = new byte[prefix.length + digest.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(digest, 0, out, prefix.length, digest.length);
        return out;
    }

    /* ====================== General helpers ====================== */

    private static boolean isJsonSerialization(String s) {
        return s.contains("\"protected\"") && s.contains("\"signature\"");
    }

    private static boolean isBerlinGroupSerialization(String s) {
        return s.contains("\"signatureData\"")
                && s.contains("\"protected\"")
                && s.contains("\"signature\"");
    }

    private static boolean isPlainJoseJsonSerialization(String s) {
        return s.contains("\"protected\"")
                && s.contains("\"signature\"")
                && !s.contains("\"signatureData\"");
    }

    private static String extractJsonValue(String json, String keyWithQuotes) {
        int i = json.indexOf(keyWithQuotes);
        if (i < 0) throw new IllegalArgumentException("Missing JSON field " + keyWithQuotes);
        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon + 1);
        int q2 = json.indexOf('"', q1 + 1);
        if (colon < 0 || q1 < 0 || q2 < 0) {
            throw new IllegalArgumentException("Malformed JSON near " + keyWithQuotes);
        }
        return json.substring(q1 + 1, q2);
    }

    private static String extractFirstStringFromJsonArray(String json, String keyWithQuotes) {
        int k = json.indexOf(keyWithQuotes);
        if (k < 0) return null;

        int colon = json.indexOf(':', k);
        if (colon < 0) return null;

        int arrStart = json.indexOf('[', colon);
        if (arrStart < 0) return null;

        int q1 = json.indexOf('"', arrStart);
        if (q1 < 0) return null;

        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;

        return json.substring(q1 + 1, q2);
    }

    private static String toJoseJsonForDss(String content) {
        if (isBerlinGroupSerialization(content)) {
            String protectedB64 = extractJsonValue(content, "\"protected\"");
            String signatureB64 = extractJsonValue(content, "\"signature\"");

            return """
            {
              "protected":"%s",
              "signature":"%s"
            }
            """.formatted(protectedB64, signatureB64).trim();
        }

        if (isPlainJoseJsonSerialization(content)) {
            return content;
        }

        String[] parts = content.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid compact JWS for DSS.");
        }

        String protectedB64 = parts[0];
        String payloadB64 = parts[1];
        String signatureB64 = parts[2];

        if (payloadB64 == null || payloadB64.isEmpty()) {
            return """
            {
              "protected":"%s",
              "signature":"%s"
            }
            """.formatted(protectedB64, signatureB64).trim();
        } else {
            return """
            {
              "payload":"%s",
              "protected":"%s",
              "signature":"%s"
            }
            """.formatted(payloadB64, protectedB64, signatureB64).trim();
        }
    }

    private byte[] loadDetachedPayloadPossiblyCanonicalized() throws Exception {
        byte[] raw = Files.readAllBytes(payloadFile);
        boolean doCanonicalize = canonicalizePayload != null && canonicalizePayload.equalsIgnoreCase("jcs");
        if (!doCanonicalize) return raw;

        String asText = new String(raw, StandardCharsets.UTF_8);
        if (!looksLikeJson(asText)) {
            throw new IllegalArgumentException("--canonicalize-payload=jcs requires a JSON payload file (object or array).");
        }
        String canonical = JsonCanonicalizerJcs.canonicalize(asText);
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    private static boolean looksLikeJson(String s) {
        int i = 0, n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) i++;
        if (i >= n) return false;
        char c = s.charAt(i);
        return c == '{' || c == '[';
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] concatToDer(byte[] jwsSignature, int fieldSizeBytes) {
        if (jwsSignature == null || jwsSignature.length != fieldSizeBytes * 2) {
            throw new IllegalArgumentException("Invalid JWS ECDSA signature length.");
        }

        byte[] r = new byte[fieldSizeBytes];
        byte[] s = new byte[fieldSizeBytes];
        System.arraycopy(jwsSignature, 0, r, 0, fieldSizeBytes);
        System.arraycopy(jwsSignature, fieldSizeBytes, s, 0, fieldSizeBytes);

        byte[] rDer = unsignedIntegerToDer(r);
        byte[] sDer = unsignedIntegerToDer(s);

        int seqLen = rDer.length + sDer.length;
        byte[] seqLenEnc = derLength(seqLen);

        byte[] out = new byte[1 + seqLenEnc.length + seqLen];
        int pos = 0;
        out[pos++] = 0x30;
        System.arraycopy(seqLenEnc, 0, out, pos, seqLenEnc.length);
        pos += seqLenEnc.length;
        System.arraycopy(rDer, 0, out, pos, rDer.length);
        pos += rDer.length;
        System.arraycopy(sDer, 0, out, pos, sDer.length);

        return out;
    }

    private static byte[] unsignedIntegerToDer(byte[] value) {
        int firstNonZero = 0;
        while (firstNonZero < value.length - 1 && value[firstNonZero] == 0) {
            firstNonZero++;
        }

        int len = value.length - firstNonZero;
        boolean needsLeadingZero = (value[firstNonZero] & 0x80) != 0;

        int contentLen = len + (needsLeadingZero ? 1 : 0);
        byte[] lenEnc = derLength(contentLen);

        byte[] out = new byte[1 + lenEnc.length + contentLen];
        int pos = 0;
        out[pos++] = 0x02;
        System.arraycopy(lenEnc, 0, out, pos, lenEnc.length);
        pos += lenEnc.length;

        if (needsLeadingZero) {
            out[pos++] = 0x00;
        }

        System.arraycopy(value, firstNonZero, out, pos, len);
        return out;
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        }

        int temp = length;
        int numBytes = 0;
        while (temp > 0) {
            numBytes++;
            temp >>= 8;
        }

        byte[] out = new byte[1 + numBytes];
        out[0] = (byte) (0x80 | numBytes);

        for (int i = numBytes; i > 0; i--) {
            out[i] = (byte) (length & 0xFF);
            length >>= 8;
        }

        return out;
    }

    /* ====================== Debug helpers ====================== */

    private void debug(String label, String value) {
        if (!debug) return;
        System.out.println("[DEBUG] " + label + ": " + value);
    }

    private void debugMultiline(String label, String value) {
        if (!debug) return;
        System.out.println("[DEBUG] " + label + ":");
        System.out.println(value);
    }

    private void debugPayload(byte[] payload, String label) throws Exception {
        if (!debug || payload == null) return;
        debug(label + " bytes", String.valueOf(payload.length));
        debug(label + " sha512 b64", sha512Base64(payload));
        debug(label + " first16 hex", toHexPrefix(payload, 16));
    }

    private static String sha512Base64(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512").digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }

    private static String toHexPrefix(byte[] data, int maxBytes) {
        if (data == null) return "null";
        int len = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        if (data.length > maxBytes) {
            sb.append(" ...");
        }
        return sb.toString();
    }

    private static String abbreviate(String s, int maxLen) {
        if (s == null) return "null";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }
}