@echo off
setlocal

set JAR=..\target\SigningAuthorisation-0.0.1-SNAPSHOT-all.jar

set PAYLOAD=.\pain001.xml
set OUT=.\result\pain001-signature.xml

set KEYSTORE=.\DSS_TrustKeyStore.p12
set KEYSTORE_TYPE=PKCS12
set KEYSTORE_PASSWORD=password
set KEY_ALIAS=ps512
set KEY_PASSWORD=password
set RES_ID=pain001.myResourceId1234


java -jar "%JAR%" sign-xml ^
  --format xades ^
  --alg PS512 ^
  --payload "%PAYLOAD%" ^
  --out "%OUT%" ^
  --keystore "%KEYSTORE%" ^
  --keystoreType "%KEYSTORE_TYPE%" ^
  --keystorePassword "%KEYSTORE_PASSWORD%" ^
  --keyAlias "%KEY_ALIAS%" ^
  --keyPassword "%KEY_PASSWORD%" ^
  --referenceURI "%RES_ID%" ^
  --debug

if errorlevel 1 (
  echo.
  echo XAdES signing failed.
  exit /b 1
)

echo.
echo XAdES signing finished successfully.
echo Signature file: %OUT%

endlocal