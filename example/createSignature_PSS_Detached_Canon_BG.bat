REM java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar sign --alg PS512 --payload Payload.json --key-dir .\ --key-file ps512_key.pem --out-format bg --out .\result\PS512_bg_detached_canon.jws --sigT CURRENT --iat --sub aPaymentResID --cert-dir .\ --cert-file ps512_cert.pem --canonicalize-payload jcs --critClaimList b64,sigT,sigD --detached

# iat preferred as it is mandatory for DSS JAdES Baseline-B
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar sign --alg PS512 --payload Payload.json --key-dir .\ --key-file ps512_key.pem --out-format bg --out .\result\PS512_bg_detached_canon.jws --iat --x5t#S256 --sub aPaymentResID --cert-dir .\ --cert-file ps512_cert.pem --canonicalize-payload jcs --critClaimList b64,sigT,sigD --detached
