
@echo ##Attention: When SigCmd is using parameter canonicalize-payload, you should use the JSON4Signature... output as input of VerifyCmd
@echo              or set parameter --canonicalize-payload jcs
@echo ## with the parameter --alg ph  the signature alg defined in protected header is used automatically

@echo --> with canonicalize-payload as input payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\result\ES512_bg_detached_canon.jws --pub-dir .\ --pub-file es512_cert.pem --payload .\result\JSON4Signaturees512_bg_detached_canon.jws.json  --detached

@echo --> with original payload as input payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --canonicalize-payload jcs --in .\result\ES512_bg_detached_canon.jws --pub-dir .\ --pub-file es512_cert.pem --payload .\Payload.json --detached


@echo --> with canonicalize-payload as input payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode eidas --alg ph --in .\result\ES512_bg_detached_canon.jws --pub-dir .\ --pub-file es512_cert.pem --payload .\result\JSON4Signaturees512_bg_detached_canon.jws.json  --truststore DSS_TrustStore.p12 --truststoreType PKCS12 --truststorePassword password --validationPolicy .\default-constraint-WebAPP.xml --detached


