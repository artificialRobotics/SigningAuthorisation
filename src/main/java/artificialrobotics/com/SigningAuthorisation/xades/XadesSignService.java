package artificialrobotics.com.SigningAuthorisation.xades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;

public final class XadesSignService {

    private final XadesKeyMaterialResolver keyMaterialResolver;
    private final XadesSignatureParametersFactory parametersFactory;

    public XadesSignService(XadesKeyMaterialResolver keyMaterialResolver,
                            XadesSignatureParametersFactory parametersFactory) {
        this.keyMaterialResolver = keyMaterialResolver;
        this.parametersFactory = parametersFactory;
    }

    public void sign(XadesSignRequest request) throws Exception {
        request.validate();

        XadesResolvedKeyMaterial keyMaterial = keyMaterialResolver.resolve(request);
        XadesSignatureParametersFactory.ResolvedXadesAlgorithm resolvedAlgorithm =
            parametersFactory.resolveAlgorithm(request.getAlg(), keyMaterial.getPrivateKey());

        byte[] xmlBytes = Files.readAllBytes(request.getPayloadFile());
        XAdESSignatureParameters parameters = parametersFactory.create(request, keyMaterial, xmlBytes);

        InMemoryDocument toSignDocument = new InMemoryDocument(
            xmlBytes,
            request.getPayloadFile().getFileName().toString(),
            MimeTypeEnum.XML
        );

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(certificateVerifier);

        debug(request, "format", request.getFormat());
        debug(request, "payload", request.getPayloadFile().toAbsolutePath().toString());
        debug(request, "out", request.getOutFile().toAbsolutePath().toString());
        debug(request, "detached reference uri", request.getDetachedReferenceUri());
        debug(request, "dss document name", request.getPayloadFile().getFileName().toString());
        debug(request, "key algorithm", keyMaterial.getPrivateKey().getAlgorithm());
        debug(request, "signing cert subject", keyMaterial.getSigningCertificate().getSubjectX500Principal().getName());
        debug(request, "resolved DSS signature algorithm", resolvedAlgorithm.getSignatureAlgorithm().name());
        debug(request, "resolved encryption algorithm", resolvedAlgorithm.getEncryptionAlgorithm().name());
        debug(request, "resolved digest algorithm", resolvedAlgorithm.getDigestAlgorithm().name());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
        debug(request, "data-to-sign length", String.valueOf(dataToSign.getBytes().length));

        SignatureValue signatureValue = signDataToSign(
            dataToSign,
            keyMaterial.getPrivateKey(),
            resolvedAlgorithm
        );

        DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

        Path outParent = request.getOutFile().toAbsolutePath().getParent();
        if (outParent != null) {
            Files.createDirectories(outParent);
        }
        signedDocument.save(request.getOutFile().toAbsolutePath().toString());

        System.out.println("Wrote detached XAdES signature: " + request.getOutFile().toAbsolutePath());
        System.out.println("Original XML payload unchanged: " + request.getPayloadFile().toAbsolutePath());
        System.out.println("Detached ds:Reference URI: " + request.getDetachedReferenceUri());
    }

    private SignatureValue signDataToSign(ToBeSigned dataToSign,
                                          PrivateKey privateKey,
                                          XadesSignatureParametersFactory.ResolvedXadesAlgorithm resolvedAlgorithm) throws Exception {
        Signature signature = Signature.getInstance(resolvedAlgorithm.getJcaSignatureName());
        if (resolvedAlgorithm.getPssParameterSpec() != null) {
            signature.setParameter(resolvedAlgorithm.getPssParameterSpec());
        }
        signature.initSign(privateKey);
        signature.update(dataToSign.getBytes());

        byte[] signatureBytes = signature.sign();
        return new SignatureValue(resolvedAlgorithm.getSignatureAlgorithm(), signatureBytes);
    }

    private void debug(XadesSignRequest request, String label, String value) {
        if (request.isDebug()) {
            System.out.println("[XADES-DEBUG] " + label + ": " + value);
        }
    }
}