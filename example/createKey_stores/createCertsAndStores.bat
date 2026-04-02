@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem =========================================================
rem Script 2
rem - nutzt vorhandene Keys + CSRs + Template.cnf
rem - erzeugt lokale Test-Zertifikate
rem - erzeugt 3 PKCS#12 Keypair-Stores
rem - erzeugt 1 gemeinsamen PKCS#12 Public-Cert-Store
rem - Dateinamen erhalten einen technisch bereinigten CN-Wert als Prefix
rem - PKCS#12 Friendly Names verwenden einen ASCII-sicheren Alias
rem - Umlaute im Zertifikat bleiben erhalten
rem
rem Parameter:
rem   --outdir <dir>
rem   --hash 256|512
rem =========================================================

set "OPENSSL=openssl"
set "OUTDIR=.\KeyMaterialAndTruststores"
set "BASE_OUTDIR="
set "TEMPLATE="
set "CHAIN="
set "KEYPASS=password"
set "P12PASS=password"
set "DAYS=825"
set "HASH_BITS=512"

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

if /I "%~1"=="--hash" (
    if "%~2"=="" (
        echo FEHLER: Fuer --hash wurde kein Wert angegeben.
        exit /b 1
    )
    if /I "%~2"=="256" (
        set "HASH_BITS=256"
    ) else if /I "%~2"=="512" (
        set "HASH_BITS=512"
    ) else (
        echo FEHLER: Ungueltiger Wert fuer --hash: %~2
        echo Erwartet: 256 oder 512
        exit /b 1
    )
    shift
    shift
    goto parse_args
)

echo FEHLER: Unbekannter Parameter: %~1
echo Erwartet: --outdir ^<Verzeichnis^> --hash ^<256^|512^>
exit /b 1

:args_done

set "BASE_OUTDIR=%OUTDIR%"
set "OUTDIR=%BASE_OUTDIR%-%HASH_BITS%"
set "TEMPLATE=%OUTDIR%\Template.cnf"
set "CHAIN=%OUTDIR%\chain.pem"

if "%HASH_BITS%"=="256" (
    set "DIGEST_NAME=sha256"
    set "RSA_PSS_SALTLEN=32"
    set "RS_LABEL=rs256"
    set "PS_LABEL=ps256"
    set "ES_LABEL=es256"
) else (
    set "DIGEST_NAME=sha512"
    set "RSA_PSS_SALTLEN=64"
    set "RS_LABEL=rs512"
    set "PS_LABEL=ps512"
    set "ES_LABEL=es512"
)

echo.
echo [1/12] Pruefe OpenSSL ...
where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo FEHLER: OpenSSL wurde nicht im PATH gefunden.
    exit /b 1
)

echo.
echo [2/12] Pruefe erforderliche Dateien ...
call :check_file "%TEMPLATE%" || exit /b 1

echo.
echo [3/12] Lese CN aus Template.cnf ...
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
call :make_cn_alias "%CN_VALUE%" CN_ALIAS
if not defined CN_ALIAS (
    echo FEHLER: CN-Alias konnte nicht erzeugt werden.
    exit /b 1
)
echo   CN            : %CN_VALUE%
echo   CN-FilePrefix : %CN_PREFIX%
echo   CN-Alias      : %CN_ALIAS%
echo   Hash          : %HASH_BITS%
echo   Digest        : %DIGEST_NAME%

set "RS_KEY=%OUTDIR%\%CN_PREFIX%-%RS_LABEL%.key.pem"
set "RS_CSR=%OUTDIR%\%CN_PREFIX%-%RS_LABEL%.csr.pem"
set "RS_CRT=%OUTDIR%\%CN_PREFIX%-%RS_LABEL%.crt.pem"
set "RS_P12=%OUTDIR%\%CN_PREFIX%-%RS_LABEL%-eidas-seal-keypair.p12"

set "PS_KEY=%OUTDIR%\%CN_PREFIX%-%PS_LABEL%.key.pem"
set "PS_CSR=%OUTDIR%\%CN_PREFIX%-%PS_LABEL%.csr.pem"
set "PS_CRT=%OUTDIR%\%CN_PREFIX%-%PS_LABEL%.crt.pem"
set "PS_P12=%OUTDIR%\%CN_PREFIX%-%PS_LABEL%-eidas-seal-keypair.p12"

set "ES_KEY=%OUTDIR%\%CN_PREFIX%-%ES_LABEL%.key.pem"
set "ES_CSR=%OUTDIR%\%CN_PREFIX%-%ES_LABEL%.csr.pem"
set "ES_CRT=%OUTDIR%\%CN_PREFIX%-%ES_LABEL%.crt.pem"
set "ES_P12=%OUTDIR%\%CN_PREFIX%-%ES_LABEL%-eidas-seal-keypair.p12"

set "ALL_CERTS_PEM=%OUTDIR%\%CN_PREFIX%-all-seal-certs-%HASH_BITS%.pem"
set "PUBLIC_CERTSTORE_P12=%OUTDIR%\%CN_PREFIX%-eidas-seals-public-certstore.p12"

call :check_file "%RS_KEY%" || exit /b 1
call :check_file "%RS_CSR%" || exit /b 1
call :check_file "%PS_KEY%" || exit /b 1
call :check_file "%PS_CSR%" || exit /b 1
call :check_file "%ES_KEY%" || exit /b 1
call :check_file "%ES_CSR%" || exit /b 1

if exist "%CHAIN%" (
    set "USE_CHAIN=1"
    echo   OK: %CHAIN% ^(optional gefunden^)
) else (
    set "USE_CHAIN=0"
    echo   HINWEIS: %CHAIN% nicht gefunden - Stores werden ohne Zertifikatskette erstellt.
)

echo.
echo [4/12] Erzeuge %RS_LABEL% Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%RS_CSR%" ^
  -signkey "%RS_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%RS_CRT%" ^
  -days %DAYS% ^
  -%DIGEST_NAME% ^
  -extfile "%TEMPLATE%" ^
  -extensions req_ext ^
  -copy_extensions copy
if errorlevel 1 (
    echo FEHLER: %RS_LABEL% Zertifikat konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [5/12] Erzeuge %PS_LABEL% Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%PS_CSR%" ^
  -signkey "%PS_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%PS_CRT%" ^
  -days %DAYS% ^
  -%DIGEST_NAME% ^
  -sigopt rsa_padding_mode:pss ^
  -sigopt rsa_pss_saltlen:%RSA_PSS_SALTLEN% ^
  -sigopt rsa_mgf1_md:%DIGEST_NAME% ^
  -extfile "%TEMPLATE%" ^
  -extensions req_ext ^
  -copy_extensions copy
if errorlevel 1 (
    echo FEHLER: %PS_LABEL% Zertifikat konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [6/12] Erzeuge %ES_LABEL% Test-Zertifikat ...
%OPENSSL% x509 -req ^
  -in "%ES_CSR%" ^
  -signkey "%ES_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%ES_CRT%" ^
  -days %DAYS% ^
  -%DIGEST_NAME% ^
  -extfile "%TEMPLATE%" ^
  -extensions req_ext ^
  -copy_extensions copy
if errorlevel 1 (
    echo FEHLER: %ES_LABEL% Zertifikat konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [7/12] Erzeuge 3 PKCS#12 Keypair-Stores ...
if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%RS_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%RS_CRT%" ^
      -certfile "%CHAIN%" ^
      -out "%RS_P12%" ^
      -name "%CN_ALIAS% - %RS_LABEL%" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%RS_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%RS_CRT%" ^
      -out "%RS_P12%" ^
      -name "%CN_ALIAS% - %RS_LABEL%" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: %RS_LABEL% Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%PS_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%PS_CRT%" ^
      -certfile "%CHAIN%" ^
      -out "%PS_P12%" ^
      -name "%CN_ALIAS% - %PS_LABEL%" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%PS_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%PS_CRT%" ^
      -out "%PS_P12%" ^
      -name "%CN_ALIAS% - %PS_LABEL%" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: %PS_LABEL% Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -inkey "%ES_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%ES_CRT%" ^
      -certfile "%CHAIN%" ^
      -out "%ES_P12%" ^
      -name "%CN_ALIAS% - %ES_LABEL%" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -inkey "%ES_KEY%" ^
      -passin pass:%KEYPASS% ^
      -in "%ES_CRT%" ^
      -out "%ES_P12%" ^
      -name "%CN_ALIAS% - %ES_LABEL%" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: %ES_LABEL% Keypair-Store konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [8/12] Bilde gemeinsamen Public-Cert-PEM-Container ...
copy /b "%RS_CRT%" + "%PS_CRT%" + "%ES_CRT%" "%ALL_CERTS_PEM%" >nul
if errorlevel 1 (
    echo FEHLER: %ALL_CERTS_PEM% konnte nicht erstellt werden.
    exit /b 1
)

echo.
echo [9/12] Erzeuge gemeinsamen PKCS#12 Public-Cert-Store ...
if "%USE_CHAIN%"=="1" (
    %OPENSSL% pkcs12 -export ^
      -nokeys ^
      -in "%ALL_CERTS_PEM%" ^
      -certfile "%CHAIN%" ^
      -out "%PUBLIC_CERTSTORE_P12%" ^
      -name "%CN_ALIAS% - Public Cert Store" ^
      -passout pass:%P12PASS%
) else (
    %OPENSSL% pkcs12 -export ^
      -nokeys ^
      -in "%ALL_CERTS_PEM%" ^
      -out "%PUBLIC_CERTSTORE_P12%" ^
      -name "%CN_ALIAS% - Public Cert Store" ^
      -passout pass:%P12PASS%
)
if errorlevel 1 (
    echo FEHLER: Public Cert-Store konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [10/12] Optional pruefen ...
echo   openssl pkcs12 -info -in "%RS_P12%" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%PS_P12%" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%ES_P12%" -passin pass:%P12PASS%
echo   openssl pkcs12 -info -in "%PUBLIC_CERTSTORE_P12%" -passin pass:%P12PASS%

echo.
echo [11/12] Fertig.
echo Erfolgreich erstellt:
echo   %RS_CRT%
echo   %PS_CRT%
echo   %ES_CRT%
echo   %RS_P12%
echo   %PS_P12%
echo   %ES_P12%
echo   %PUBLIC_CERTSTORE_P12%
echo   %ALL_CERTS_PEM%
echo.
echo Private-Key-Passwort: %KEYPASS%
echo PKCS#12-Passwort:     %P12PASS%
echo.

echo [12/12] Zusammenfassung:
echo   RSA PKCS#1 v1.5 : %RS_LABEL%
echo   RSA-PSS         : %PS_LABEL%
echo   ECDSA           : %ES_LABEL%
echo   OUTDIR          : %OUTDIR%
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
set "VALUE=!VALUE:Ä=Ae!"
set "VALUE=!VALUE:Ö=Oe!"
set "VALUE=!VALUE:Ü=Ue!"
set "VALUE=!VALUE:ä=ae!"
set "VALUE=!VALUE:ö=oe!"
set "VALUE=!VALUE:ü=ue!"
set "VALUE=!VALUE:ß=ss!"
set "VALUE=!VALUE: =_!"
endlocal & set "%~2=%VALUE%"
exit /b 0

:make_cn_alias
setlocal EnableDelayedExpansion
set "VALUE=%~1"
set "VALUE=!VALUE:Ä=Ae!"
set "VALUE=!VALUE:Ö=Oe!"
set "VALUE=!VALUE:Ü=Ue!"
set "VALUE=!VALUE:ä=ae!"
set "VALUE=!VALUE:ö=oe!"
set "VALUE=!VALUE:ü=ue!"
set "VALUE=!VALUE:ß=ss!"
endlocal & set "%~2=%VALUE%"
exit /b 0