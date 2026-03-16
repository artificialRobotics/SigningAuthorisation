keytool -importcert -alias ps512 -file ps512_cert.pem -keystore DSS_TrustStore.p12 -storetype PKCS12 -storepass password
keytool -importcert -alias es512 -file es512_cert.pem -keystore DSS_TrustStore.p12 -storetype PKCS12 -storepass password
keytool -list -keystore DSS_TrustStore.p12 -storetype PKCS12 -storepass password


openssl pkcs12 -export -inkey ps512_key.pem -in ps512_cert.pem -out DSS_TrustKeyStore.p12 -name "ps512" -passout pass:password