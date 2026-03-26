@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem =========================================================
rem Script 2
rem - nutzt vorhandene Keys + CSRs + Template.cnf
rem - erzeugt lokale Test-Zertifikate
rem - erzeugt 3 PKCS#12 Keypair-Stores
rem - erzeugt 1 gemeinsamen PKCS#12 Public-Cert-Store
rem - Dateinamen erhalten den CN-Wert als Prefix
rem =========================================================

set "OPENSSL=openssl"
set "OUTDIR=.\KeyMaterialAndTruststores"
set "TEMPLATE=%OUTDIR%\Template.cnf"
set "CHAIN=%OUTDIR%\chain.pem"
set "KEYPASS=password"
set "P12PASS=password"
set "DAYS=825"

rem use --outdir if given
:parse_args
if "%~1"=="" goto args_done

if /I "%~1"=="--outdir" (
    if "%~2"=="" (
        echo FEHLER: Fuer --outdir wurde kein Verzeichnis angegeben.
        exit /b 1
    )
    set "OUTDIR=%~2"
    shift
    shift
    goto parse_args
)

echo FEHLER: Unbekannter Parameter: %~1
echo Erwartet: --outdir ^<Verzeichnis^>
exit /b 1

:args_done
rem end --outdir

set "TEMPLATE=%OUTDIR%\Template.cnf"
set "CHAIN=%OUTDIR%\chain.pem"

echo.
echo [1/11] Pruefe OpenSSL ...
where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo FEHLER: OpenSSL wurde nicht im PATH gefunden.
    exit /b 1
)

echo.
echo [2/11] Pruefe erforderliche Dateien ...
call :check_file "%TEMPLATE%" || exit /b 1

echo.
echo [3/11] Lese CN aus Template.cnf ...
call :read_cn "%TEMPLATE%" CN_VALUE
if not defined CN_VALUE (
    echo FEHLER: CN konnte aus %TEMPLATE% nicht gelesen werden.
    exit /b 1
)
call :make_cn_prefix "%CN_VALUE%" CN_PREFIX
if not defined CN_PREFIX (
    echo FEHLER: CN-Prefix konnte nicht erzeugt werden.
    exit /b 1
)
echo   CN        : %CN_VALUE%
echo   CN-Prefix : %CN_PREFIX%

set "RS512_KEY=%OUTDIR%\%CN_PREFIX%-rs512.key.pem"
set "RS512_CSR=%OUTDIR%\%CN_PREFIX%-rs512.csr.pem"
set "RS512_CRT=%OUTDIR%\%CN_PREFIX%-rs512.crt.pem"
set "RS512_P12=%OUTDIR%\%CN_PREFIX%-rs512-eidas-seal-keypair.p12"

set "PS512_KEY=%OUTDIR%\%CN_PREFIX%-ps512.key.pem"
set "PS512_CSR=%OUTDIR%\%CN_PREFIX%-ps512.csr.pem"
set "PS512_CRT=%OUTDIR%\%CN_PREFIX%-ps512.crt.pem"
set "PS512_P12=%OUTDIR%\%CN_PREFIX%-ps512-eidas-seal-keypair.p12"

set "ES512_KEY=%OUTDIR%\%CN_PREFIX%-es512.key.pem"
set "ES512_CSR=%OUTDIR%\%CN_PREFIX%-es512.csr.pem"
set "ES512_CRT=%OUTDIR%\%CN_PREFIX%-es512.crt.pem"
set "ES512_P12=%OUTDIR%\%CN_PREFIX%-es512-eidas-seal-keypair.p12"

set "ALL_CERTS_PEM=%OUTDIR%\%CN_PREFIX%-all-seal-certs.pem"
set "PUBLIC_CERTSTORE_P12=%OUTDIR%\%CN_PREFIX%-eidas-seals-public-certstore.p12"

call :check_file "%RS512_KEY%" || exit /b 1
call :check_file "%RS512_CSR%" || exit /b 1
call :check_file "%PS512_KEY%" || exit /b 1
call :check_file "%PS512_CSR%" || exit /b 1
call :check_file "%ES512_KEY%" || exit /b 1
call :check_file "%ES512_CSR%" || exit /b 1

if exist "%CHAIN%" (
    set "USE_CHAIN=1"
    echo   OK: %CHAIN% ^(optional gefunden^)
) else (
    set "USE_CHAIN=0"
    echo   HINWEIS: %CHAIN% nicht gefunden - Stores werden ohne Zertifikatskette erstellt.
)

echo.
echo [4/11] Erzeuge RS512 Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%RS512_CSR%" ^
  -signkey "%RS512_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%RS512_CRT%" ^
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
echo [5/11] Erzeuge PS512 Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%PS512_CSR%" ^
  -signkey "%PS512_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%PS512_CRT%" ^
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
echo [6/11] Erzeuge ES512 Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%ES512_CSR%" ^
  -signkey "%ES512_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%ES512_CRT%" ^
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
echo [7/11] Erzeuge 3 PKCS#12 Keypair-Stores ...
if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%RS512_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%RS512_CRT%" ^
      -certfile "%CHAIN%" ^
      -out "%RS512_P12%" ^
      -name "%CN_VALUE% - RS512" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%RS512_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%RS512_CRT%" ^
      -out "%RS512_P12%" ^
      -name "%CN_VALUE% - RS512" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: RS512 Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%PS512_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%PS512_CRT%" ^
      -certfile "%CHAIN%" ^
      -out "%PS512_P12%" ^
      -name "%CN_VALUE% - PS512" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%PS512_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%PS512_CRT%" ^
      -out "%PS512_P12%" ^
      -name "%CN_VALUE% - PS512" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: PS512 Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%ES512_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%ES512_CRT%" ^
      -certfile "%CHAIN%" ^
      -out "%ES512_P12%" ^
      -name "%CN_VALUE% - ES512" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%ES512_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%ES512_CRT%" ^
      -out "%ES512_P12%" ^
      -name "%CN_VALUE% - ES512" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: ES512 Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [8/11] Bilde gemeinsamen Public-Cert-PEM-Container ...
copy /b "%RS512_CRT%" + "%PS512_CRT%" + "%ES512_CRT%" "%ALL_CERTS_PEM%" >nul
if errorlevel 1 (
    echo FEHLER: %ALL_CERTS_PEM% konnte nicht erstellt werden.
    exit /b 1
)

echo.
echo [9/11] Erzeuge gemeinsamen PKCS#12 Public-Cert-Store ...
if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -nokeys ^
      -in "%ALL_CERTS_PEM%" ^
      -certfile "%CHAIN%" ^
      -out "%PUBLIC_CERTSTORE_P12%" ^
      -name "%CN_VALUE% - Public Cert Store" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -nokeys ^
      -in "%ALL_CERTS_PEM%" ^
      -out "%PUBLIC_CERTSTORE_P12%" ^
      -name "%CN_VALUE% - Public Cert Store" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: Public Cert-Store konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [10/11] Optional pruefen ...
echo   openssl pkcs12 -info -in "%RS512_P12%" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%PS512_P12%" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%ES512_P12%" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%PUBLIC_CERTSTORE_P12%" -passin pass:%P12PASS%

echo.
echo [11/11] Fertig.
echo Erfolgreich erstellt:
echo   %RS512_CRT%
echo   %PS512_CRT%
echo   %ES512_CRT%
echo   %RS512_P12%
echo   %PS512_P12%
echo   %ES512_P12%
echo   %PUBLIC_CERTSTORE_P12%
echo.
echo Private-Key-Passwort: %KEYPASS%
echo PKCS#12-Passwort:     %P12PASS%
echo.
exit /b 0

:check_file
if not exist %1 (
    echo FEHLER: Datei nicht gefunden: %~1
    exit /b 1
)
echo   OK: %~1
exit /b 0

:read_cn
setlocal EnableExtensions DisableDelayedExpansion
set "FILE=%~1"
set "VALUE="
for /f "usebackq tokens=1,* delims==" %%A in ("%FILE%") do (
    set "LEFT=%%A"
    set "RIGHT=%%B"
    setlocal EnableDelayedExpansion
    set "LEFT=!LEFT: =!"
    if /I "!LEFT!"=="CN" (
        endlocal
        set "VALUE=%%B"
        goto read_cn_done
    )
    endlocal
)
:read_cn_done
if defined VALUE (
    for /f "tokens=* delims= " %%Z in ("%VALUE%") do set "VALUE=%%Z"
)
endlocal & set "%~2=%VALUE%"
exit /b 0

:make_cn_prefix
setlocal EnableDelayedExpansion
set "VALUE=%~1"
set "VALUE=!VALUE: =_!"
endlocal & set "%~2=%VALUE%"
exit /b 0