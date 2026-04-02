@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem =========================================================
rem Script 1
rem - nutzt vorhandenes Template.cnf
rem - erzeugt RSxxx / PSxxx / ESxxx Private Keys
rem - erzeugt RSxxx / PSxxx / ESxxx CSRs
rem - Dateinamen erhalten einen technisch bereinigten CN-Wert als Prefix
rem - Umlaute im Zertifikat/CSR bleiben erhalten
rem
rem Parameter:
rem   --outdir <dir>
rem   --cnf <file>
rem   --hash 256|512
rem =========================================================

set "OPENSSL=openssl"
set "OUTDIR=.\KeyMaterialAndTruststores"
set "BASE_OUTDIR="
set "TEMPLATE="
set "KEYPASS=password"
set "CNF_SOURCE="
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

if /I "%~1"=="--cnf" (
    if "%~2"=="" (
        echo FEHLER: Fuer --cnf wurde keine Datei angegeben.
        exit /b 1
    )
    set "CNF_SOURCE=%~2"
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
echo Erwartet: --outdir ^<Verzeichnis^> --cnf ^<Datei^> --hash ^<256^|512^>
exit /b 1

:args_done

set "BASE_OUTDIR=%OUTDIR%"
set "OUTDIR=%BASE_OUTDIR%-%HASH_BITS%"
set "TEMPLATE=%OUTDIR%\Template.cnf"

if "%HASH_BITS%"=="256" (
    set "DIGEST_NAME=sha256"
    set "RSA_PSS_SALTLEN=32"
    set "EC_CURVE=P-256"
    set "RS_LABEL=rs256"
    set "PS_LABEL=ps256"
    set "ES_LABEL=es256"
) else (
    set "DIGEST_NAME=sha512"
    set "RSA_PSS_SALTLEN=64"
    set "EC_CURVE=P-521"
    set "RS_LABEL=rs512"
    set "PS_LABEL=ps512"
    set "ES_LABEL=es512"
)

echo.
echo [1/10] Pruefe OpenSSL ...
where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo FEHLER: OpenSSL wurde nicht im PATH gefunden.
    exit /b 1
)

echo.
echo [2/10] Stelle Ausgabeordner sicher ...
if not exist "%OUTDIR%" (
    mkdir "%OUTDIR%"
    if errorlevel 1 (
        echo FEHLER: Ausgabeordner konnte nicht erstellt werden: %OUTDIR%
        exit /b 1
    )
)
echo   OK: %OUTDIR%

echo.
echo [3/10] Pruefe oder kopiere Template.cnf ...
if defined CNF_SOURCE (
    if not exist "%~dp0%CNF_SOURCE%" (
        echo FEHLER: Angegebene --cnf Datei nicht gefunden: %~dp0%CNF_SOURCE%
        exit /b 1
    )
    copy /Y "%~dp0%CNF_SOURCE%" "%TEMPLATE%" >nul
    if errorlevel 1 (
        echo FEHLER: %~dp0%CNF_SOURCE% konnte nicht nach %TEMPLATE% kopiert werden.
        exit /b 1
    )
    echo   OK: %~dp0%CNF_SOURCE% --^> %TEMPLATE%
) else (
    if not exist "%TEMPLATE%" (
        echo FEHLER: Template-Datei nicht gefunden: %TEMPLATE%
        exit /b 1
    )
    echo   OK: %TEMPLATE%
)

echo.
echo [4/10] Lese CN aus Template.cnf ...
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
echo   CN            : %CN_VALUE%
echo   CN-FilePrefix : %CN_PREFIX%
echo   Hash          : %HASH_BITS%
echo   Digest        : %DIGEST_NAME%
echo   EC Curve      : %EC_CURVE%

set "RS_KEY=%OUTDIR%\%CN_PREFIX%-%RS_LABEL%.key.pem"
set "RS_CSR=%OUTDIR%\%CN_PREFIX%-%RS_LABEL%.csr.pem"
set "PS_KEY=%OUTDIR%\%CN_PREFIX%-%PS_LABEL%.key.pem"
set "PS_CSR=%OUTDIR%\%CN_PREFIX%-%PS_LABEL%.csr.pem"
set "ES_KEY=%OUTDIR%\%CN_PREFIX%-%ES_LABEL%.key.pem"
set "ES_CSR=%OUTDIR%\%CN_PREFIX%-%ES_LABEL%.csr.pem"

echo.
echo [5/10] Erzeuge %RS_LABEL% Private Key ...
%OPENSSL% genpkey ^
  -algorithm RSA ^
  -pkeyopt rsa_keygen_bits:3072 ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%RS_KEY%"
if errorlevel 1 (
    echo FEHLER: %RS_LABEL% Key konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [6/10] Erzeuge %RS_LABEL% CSR ...
%OPENSSL% req -new ^
  -utf8 ^
  -batch ^
  -key "%RS_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%RS_CSR%" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -%DIGEST_NAME%
if errorlevel 1 (
    echo FEHLER: %RS_LABEL% CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [7/10] Erzeuge %PS_LABEL% Private Key und CSR ...
%OPENSSL% genpkey ^
  -algorithm RSA-PSS ^
  -pkeyopt rsa_keygen_bits:3072 ^
  -pkeyopt rsa_pss_keygen_md:%DIGEST_NAME% ^
  -pkeyopt rsa_pss_keygen_mgf1_md:%DIGEST_NAME% ^
  -pkeyopt rsa_pss_keygen_saltlen:%RSA_PSS_SALTLEN% ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%PS_KEY%"
if errorlevel 1 (
    echo FEHLER: %PS_LABEL% Key konnte nicht erzeugt werden.
    exit /b 1
)

%OPENSSL% req -new ^
  -utf8 ^
  -batch ^
  -key "%PS_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%PS_CSR%" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -%DIGEST_NAME% ^
  -sigopt rsa_padding_mode:pss ^
  -sigopt rsa_pss_saltlen:%RSA_PSS_SALTLEN% ^
  -sigopt rsa_mgf1_md:%DIGEST_NAME%
if errorlevel 1 (
    echo FEHLER: %PS_LABEL% CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [8/10] Erzeuge %ES_LABEL% Private Key und CSR ...
%OPENSSL% genpkey ^
  -algorithm EC ^
  -pkeyopt ec_paramgen_curve:%EC_CURVE% ^
  -pkeyopt ec_param_enc:named_curve ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%ES_KEY%"
if errorlevel 1 (
    echo FEHLER: %ES_LABEL% Key konnte nicht erzeugt werden.
    exit /b 1
)

%OPENSSL% req -new ^
  -utf8 ^
  -batch ^
  -key "%ES_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%ES_CSR%" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -%DIGEST_NAME%
if errorlevel 1 (
    echo FEHLER: %ES_LABEL% CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [9/10] Fertig.
echo Erfolgreich erstellt:
echo   %RS_KEY%
echo   %RS_CSR%
echo   %PS_KEY%
echo   %PS_CSR%
echo   %ES_KEY%
echo   %ES_CSR%
echo.
echo Verwendetes Template:
echo   %TEMPLATE%
echo.
echo Private-Key-Passwort: %KEYPASS%
echo.

echo [10/10] Zusammenfassung:
echo   RSA PKCS#1 v1.5 : %RS_LABEL%
echo   RSA-PSS         : %PS_LABEL%
echo   ECDSA           : %ES_LABEL%
echo   OUTDIR          : %OUTDIR%
echo.
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