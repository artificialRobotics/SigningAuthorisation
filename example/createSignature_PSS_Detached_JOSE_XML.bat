
java -jar ../target/SigningAuthorisation-0.0.1-SNAPSHOT-all.jar sign --alg RS512 --payload pain001.xml --key-dir .\ --key-file ps512_key.pem --out-format json --out .\result\RS512_jose_detached_XML.jws --iat --x5t#S256 --sub aPaymentResID --cert-dir .\ --cert-file ps512_cert.pem --critClaimList b64,sigD --detached
