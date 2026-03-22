@echo off
setlocal EnableExtensions

rem =========================================================
rem Script 1
rem - nutzt vorhandenes Template.cnf
rem - erzeugt RS512 / PS512 / ES512 Private Keys
rem - erzeugt RS512 / PS512 / ES512 CSRs
rem =========================================================

set "OPENSSL=openssl"
set "OUTDIR=.\KeyMaterialAndTruststores"
set "TEMPLATE=%OUTDIR%\Template.cnf"
set "KEYPASS=password"

echo.
echo [1/7] Pruefe OpenSSL ...
where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo FEHLER: OpenSSL wurde nicht im PATH gefunden.
    exit /b 1
)

echo.
echo [2/7] Pruefe Ausgabeordner ...
if not exist "%OUTDIR%" (
    echo FEHLER: Ausgabeordner nicht gefunden: %OUTDIR%
    exit /b 1
)
echo   OK: %OUTDIR%

echo.
echo [3/7] Pruefe Template.cnf ...
if not exist "%TEMPLATE%" (
    echo FEHLER: Template-Datei nicht gefunden: %TEMPLATE%
    exit /b 1
)
echo   OK: %TEMPLATE%

echo.
echo [4/7] Erzeuge RS512 Private Key ...
%OPENSSL% genpkey ^
  -algorithm RSA ^
  -pkeyopt rsa_keygen_bits:3072 ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%OUTDIR%\rs512.key.pem"
if errorlevel 1 (
    echo FEHLER: RS512 Key konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [5/7] Erzeuge RS512 CSR ...
%OPENSSL% req -new ^
  -batch ^
  -key "%OUTDIR%\rs512.key.pem" ^
  -passin pass:%KEYPASS% ^
  -out "%OUTDIR%\rs512.csr.pem" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -sha512
if errorlevel 1 (
    echo FEHLER: RS512 CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [6/7] Erzeuge PS512 Private Key und CSR ...
%OPENSSL% genpkey ^
  -algorithm RSA-PSS ^
  -pkeyopt rsa_keygen_bits:3072 ^
  -pkeyopt rsa_pss_keygen_md:sha512 ^
  -pkeyopt rsa_pss_keygen_mgf1_md:sha512 ^
  -pkeyopt rsa_pss_keygen_saltlen:64 ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%OUTDIR%\ps512.key.pem"
if errorlevel 1 (
    echo FEHLER: PS512 Key konnte nicht erzeugt werden.
    exit /b 1
)

%OPENSSL% req -new ^
  -batch ^
  -key "%OUTDIR%\ps512.key.pem" ^
  -passin pass:%KEYPASS% ^
  -out "%OUTDIR%\ps512.csr.pem" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -sha512 ^
  -sigopt rsa_padding_mode:pss ^
  -sigopt rsa_pss_saltlen:64 ^
  -sigopt rsa_mgf1_md:sha512
if errorlevel 1 (
    echo FEHLER: PS512 CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [7/7] Erzeuge ES512 Private Key und CSR ...
%OPENSSL% genpkey ^
  -algorithm EC ^
  -pkeyopt ec_paramgen_curve:P-521 ^
  -pkeyopt ec_param_enc:named_curve ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%OUTDIR%\es512.key.pem"
if errorlevel 1 (
    echo FEHLER: ES512 Key konnte nicht erzeugt werden.
    exit /b 1
)

%OPENSSL% req -new ^
  -batch ^
  -key "%OUTDIR%\es512.key.pem" ^
  -passin pass:%KEYPASS% ^
  -out "%OUTDIR%\es512.csr.pem" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -sha512
if errorlevel 1 (
    echo FEHLER: ES512 CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo Erfolgreich erstellt:
echo   %OUTDIR%\rs512.key.pem
echo   %OUTDIR%\rs512.csr.pem
echo   %OUTDIR%\ps512.key.pem
echo   %OUTDIR%\ps512.csr.pem
echo   %OUTDIR%\es512.key.pem
echo   %OUTDIR%\es512.csr.pem
echo.
echo Verwendetes Template:
echo   %TEMPLATE%
echo.
echo Private-Key-Passwort: %KEYPASS%
echo.
exit /b 0