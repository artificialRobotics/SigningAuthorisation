
@echo ##Attention: When SigCmd is using parameter canonicalize-payload, you should use the JSON4Signature... output as input of VerifyCmd
@echo              or set parameter --canonicalize-payload jcs
@echo ## with the parameter --alg ph  the signature alg defined in protected header is used automatically

@echo --> with canonicalize-payload as payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\MyJSON_ps512_compact_detached_canon.jws --pub-dir .\ --pub-file meine_test_gmbh_cert.pem --payload JSON4SignatureMyJSON_ps512_compact_detached_canon.jws  --detached

@echo --> with original payload as payload
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg ph --in .\MyJSON_ps512_compact_detached_canon.jws --pub-dir .\ --pub-file meine_test_gmbh_cert.pem --payload MyJSON.json --canonicalize-payload jcs --detached

