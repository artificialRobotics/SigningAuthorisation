@echo off
setlocal

set JAR=..\target\SigningAuthorisation-0.0.1-SNAPSHOT-all.jar

java -jar "%JAR%" verify-xml ^
  --format xades ^
  --in ".\result\pain001-signature.xml" ^
  --payload ".\pain001.xml" ^
  --truststore ".\DSS_TrustStore.p12" ^
  --truststoreType "PKCS12" ^
  --truststorePassword "password" ^
  --debug

if errorlevel 1 (
  echo.
  echo XAdES verification failed.
  exit /b 1
)

echo.
echo XAdES verification finished successfully.

endlocal