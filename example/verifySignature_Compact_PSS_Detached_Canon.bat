
@echo ##Attention: When SigCmd is using parameter canonicalize-payload, you should use the JSON4Signature... output as input of VerifyCmd

java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar verify --mode crypto --alg PS512 --in .\MyJSON_ps512_compact_detached.jws --pub-dir .\ --pub-file meine_test_gmbh_cert.pem --payload JSON4SignatureMyJSON_ps512_compact_detached.jws --detached