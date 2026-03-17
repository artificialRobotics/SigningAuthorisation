REM @echo off
REM --truststore <file>
REM --truststoreType <PKCS12|jks>
REM --truststorePassword <password>
REM --validationPolicy <xml-file>


@echo ##Attention: When SigCmd is using parameter canonicalize-payload, you should use the JSON4Signature... output as input of VerifyCmd
@echo              or set parameter --canonicalize-payload jcs
@echo ## with the parameter --alg ph  the signature alg defined in protected header is used automatically


@echo --> with original payload as payload
echo =================- JSON canon payload crypto
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload Payload.json --canonicalize-payload jcs --truststore DSS_TrustStore.p12 --truststoreType PKCS12 --truststorePassword password --validationPolicy .\custom-validation-policy.xml --detached


echo =================- JSON payload crypto
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload .\result\JSON4Signatureps512_bg_detached_canon.jws.json --validationPolicy .\default-constraint-WebAPP.xml --detached --debug


echo =================- JSON payload eidas
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode eidas --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload .\result\JSON4Signatureps512_bg_detached_canon.jws.json --truststore DSS_TrustKeyStore.p12 --truststoreType PKCS12 --truststorePassword password --validationPolicy .\default-constraint-WebAPP.xml --detached --debug

echo =================- Hash payload crypto
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payloadHashFile .\result\HASH4SignaturePS512_bg_detached_canon.jws.txt --validationPolicy .\default-constraint-WebAPP.xml --detached


echo =================- Hash payload mixed
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode mixed --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payloadHashFile .\result\HASH4SignaturePS512_bg_detached_canon.jws.txt --truststore DSS_TrustStore.p12 --truststoreType PKCS12 --truststorePassword password --validationPolicy .\default-constraint-WebAPP.xml --detached


pause