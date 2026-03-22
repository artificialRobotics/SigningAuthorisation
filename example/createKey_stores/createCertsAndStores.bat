@echo off
setlocal EnableExtensions

rem =========================================================
rem Script 2
rem - nutzt vorhandene Keys + CSRs + Template.cnf
rem - erzeugt lokale Test-Zertifikate
rem - erzeugt 3 PKCS#12 Keypair-Stores
rem - erzeugt 1 gemeinsamen PKCS#12 Public-Cert-Store
rem =========================================================

set "OPENSSL=openssl"
set "OUTDIR=.\KeyMaterialAndTruststores"
set "TEMPLATE=%OUTDIR%\Template.cnf"
set "CHAIN=%OUTDIR%\chain.pem"
set "KEYPASS=password"
set "P12PASS=password"
set "DAYS=825"

echo.
echo [1/9] Pruefe OpenSSL ...
where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo FEHLER: OpenSSL wurde nicht im PATH gefunden.
    exit /b 1
)

echo.
echo [2/9] Pruefe erforderliche Dateien ...
call :check_file "%TEMPLATE%" || exit /b 1
call :check_file "%OUTDIR%\rs512.key.pem" || exit /b 1
call :check_file "%OUTDIR%\rs512.csr.pem" || exit /b 1
call :check_file "%OUTDIR%\ps512.key.pem" || exit /b 1
call :check_file "%OUTDIR%\ps512.csr.pem" || exit /b 1
call :check_file "%OUTDIR%\es512.key.pem" || exit /b 1
call :check_file "%OUTDIR%\es512.csr.pem" || exit /b 1

if exist "%CHAIN%" (
    set "USE_CHAIN=1"
    echo   OK: %CHAIN% ^(optional gefunden^)
) else (
    set "USE_CHAIN=0"
    echo   HINWEIS: %CHAIN% nicht gefunden - Stores werden ohne Zertifikatskette erstellt.
)

echo.
echo [3/9] Erzeuge RS512 Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%OUTDIR%\rs512.csr.pem" ^
  -signkey "%OUTDIR%\rs512.key.pem" ^
  -passin pass:%KEYPASS% ^
  -out "%OUTDIR%\rs512.crt.pem" ^
  -days %DAYS% ^
  -sha512 ^
  -extfile "%TEMPLATE%" ^
  -extensions req_ext ^
  -copy_extensions copy
if errorlevel 1 (
    echo FEHLER: RS512 Zertifikat konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [4/9] Erzeuge PS512 Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%OUTDIR%\ps512.csr.pem" ^
  -signkey "%OUTDIR%\ps512.key.pem" ^
  -passin pass:%KEYPASS% ^
  -out "%OUTDIR%\ps512.crt.pem" ^
  -days %DAYS% ^
  -sha512 ^
  -sigopt rsa_padding_mode:pss ^
  -sigopt rsa_pss_saltlen:64 ^
  -sigopt rsa_mgf1_md:sha512 ^
  -extfile "%TEMPLATE%" ^
  -extensions req_ext ^
  -copy_extensions copy
if errorlevel 1 (
    echo FEHLER: PS512 Zertifikat konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [5/9] Erzeuge ES512 Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%OUTDIR%\es512.csr.pem" ^
  -signkey "%OUTDIR%\es512.key.pem" ^
  -passin pass:%KEYPASS% ^
  -out "%OUTDIR%\es512.crt.pem" ^
  -days %DAYS% ^
  -sha512 ^
  -extfile "%TEMPLATE%" ^
  -extensions req_ext ^
  -copy_extensions copy
if errorlevel 1 (
    echo FEHLER: ES512 Zertifikat konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [6/9] Erzeuge 3 PKCS#12 Keypair-Stores ...
if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%OUTDIR%\rs512.key.pem" ^
      -passin pass:%KEYPASS% ^
      -in "%OUTDIR%\rs512.crt.pem" ^
      -certfile "%CHAIN%" ^
      -out "%OUTDIR%\rs512-eidas-seal-keypair.p12" ^
      -name "Musterfirma Payment Hub eSeal - RS512" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%OUTDIR%\rs512.key.pem" ^
      -passin pass:%KEYPASS% ^
      -in "%OUTDIR%\rs512.crt.pem" ^
      -out "%OUTDIR%\rs512-eidas-seal-keypair.p12" ^
      -name "Musterfirma Payment Hub eSeal - RS512" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: RS512 Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%OUTDIR%\ps512.key.pem" ^
      -passin pass:%KEYPASS% ^
      -in "%OUTDIR%\ps512.crt.pem" ^
      -certfile "%CHAIN%" ^
      -out "%OUTDIR%\ps512-eidas-seal-keypair.p12" ^
      -name "Musterfirma Payment Hub eSeal - PS512" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%OUTDIR%\ps512.key.pem" ^
      -passin pass:%KEYPASS% ^
      -in "%OUTDIR%\ps512.crt.pem" ^
      -out "%OUTDIR%\ps512-eidas-seal-keypair.p12" ^
      -name "Musterfirma Payment Hub eSeal - PS512" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: PS512 Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%OUTDIR%\es512.key.pem" ^
      -passin pass:%KEYPASS% ^
      -in "%OUTDIR%\es512.crt.pem" ^
      -certfile "%CHAIN%" ^
      -out "%OUTDIR%\es512-eidas-seal-keypair.p12" ^
      -name "Musterfirma Payment Hub eSeal - ES512" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%OUTDIR%\es512.key.pem" ^
      -passin pass:%KEYPASS% ^
      -in "%OUTDIR%\es512.crt.pem" ^
      -out "%OUTDIR%\es512-eidas-seal-keypair.p12" ^
      -name "Musterfirma Payment Hub eSeal - ES512" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: ES512 Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [7/9] Bilde gemeinsamen Public-Cert-PEM-Container ...
copy /b "%OUTDIR%\rs512.crt.pem" + "%OUTDIR%\ps512.crt.pem" + "%OUTDIR%\es512.crt.pem" "%OUTDIR%\all-seal-certs.pem" >nul
if errorlevel 1 (
    echo FEHLER: all-seal-certs.pem konnte nicht erstellt werden.
    exit /b 1
)

echo.
echo [8/9] Erzeuge gemeinsamen PKCS#12 Public-Cert-Store ...
if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -nokeys ^
      -in "%OUTDIR%\all-seal-certs.pem" ^
      -certfile "%CHAIN%" ^
      -out "%OUTDIR%\eidas-seals-public-certstore.p12" ^
      -name "Musterfirma Payment Hub eSeal - Public Cert Store" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -nokeys ^
      -in "%OUTDIR%\all-seal-certs.pem" ^
      -out "%OUTDIR%\eidas-seals-public-certstore.p12" ^
      -name "Musterfirma Payment Hub eSeal - Public Cert Store" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: Public Cert-Store konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [9/9] Fertig.
echo Erfolgreich erstellt:
echo   %OUTDIR%\rs512.crt.pem
echo   %OUTDIR%\ps512.crt.pem
echo   %OUTDIR%\es512.crt.pem
echo   %OUTDIR%\rs512-eidas-seal-keypair.p12
echo   %OUTDIR%\ps512-eidas-seal-keypair.p12
echo   %OUTDIR%\es512-eidas-seal-keypair.p12
echo   %OUTDIR%\eidas-seals-public-certstore.p12
echo.
echo Private-Key-Passwort: %KEYPASS%
echo PKCS#12-Passwort:     %P12PASS%
echo.
echo Optional pruefen:
echo   openssl pkcs12 -info -in "%OUTDIR%\rs512-eidas-seal-keypair.p12" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%OUTDIR%\ps512-eidas-seal-keypair.p12" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%OUTDIR%\es512-eidas-seal-keypair.p12" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%OUTDIR%\eidas-seals-public-certstore.p12" -passin pass:%P12PASS%
echo.
exit /b 0

:check_file
if not exist %1 (
    echo FEHLER: Datei nicht gefunden: %~1
    exit /b 1
)
echo   OK: %~1
exit /b 0