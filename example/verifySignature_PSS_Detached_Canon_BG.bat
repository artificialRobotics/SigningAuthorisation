
@echo ##Attention: When SigCmd is using parameter canonicalize-payload, you should use the JSON4Signature... output as input of VerifyCmd
@echo              or set parameter --canonicalize-payload jcs
@echo ## with the parameter --alg ph  the signature alg defined in protected header is used automatically

@echo --> with canonicalize-payload as payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload .\result\JSON4Signatureps512_bg_detached_canon.jws.json  --detached

@echo --> with original payload as payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\result\PS512_bg_detached_canon.jws --pub-dir .\ --pub-file ps512_cert.pem --payload Payload.json --canonicalize-payload jcs --detached

