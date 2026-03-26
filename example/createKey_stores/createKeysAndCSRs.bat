@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem =========================================================
rem Script 1
rem - nutzt vorhandenes Template.cnf
rem - erzeugt RS512 / PS512 / ES512 Private Keys
rem - erzeugt RS512 / PS512 / ES512 CSRs
rem - Dateinamen erhalten den CN-Wert als Prefix
rem =========================================================

set "OPENSSL=openssl"
set "OUTDIR=.\KeyMaterialAndTruststores"
set "TEMPLATE=%OUTDIR%\Template.cnf"
set "KEYPASS=password"
set "CNF_SOURCE="

rem processing of parameters --outdir and --cnf if given
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

echo FEHLER: Unbekannter Parameter: %~1
echo Erwartet: --outdir ^<Verzeichnis^> --cnf ^<Datei^>
exit /b 1

:args_done
rem end --outdir --cnf

set "TEMPLATE=%OUTDIR%\Template.cnf"

echo.
echo [1/9] Pruefe OpenSSL ...
where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo FEHLER: OpenSSL wurde nicht im PATH gefunden.
    exit /b 1
)

echo.
echo [2/9] Stelle Ausgabeordner sicher ...
if not exist "%OUTDIR%" (
    mkdir "%OUTDIR%"
    if errorlevel 1 (
        echo FEHLER: Ausgabeordner konnte nicht erstellt werden: %OUTDIR%
        exit /b 1
    )
)
echo   OK: %OUTDIR%

echo.
echo [3/9] Pruefe oder kopiere Template.cnf ...
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
echo [4/9] Lese CN aus Template.cnf ...
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
set "PS512_KEY=%OUTDIR%\%CN_PREFIX%-ps512.key.pem"
set "PS512_CSR=%OUTDIR%\%CN_PREFIX%-ps512.csr.pem"
set "ES512_KEY=%OUTDIR%\%CN_PREFIX%-es512.key.pem"
set "ES512_CSR=%OUTDIR%\%CN_PREFIX%-es512.csr.pem"

echo.
echo [5/9] Erzeuge RS512 Private Key ...
%OPENSSL% genpkey ^
  -algorithm RSA ^
  -pkeyopt rsa_keygen_bits:3072 ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%RS512_KEY%"
if errorlevel 1 (
    echo FEHLER: RS512 Key konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [6/9] Erzeuge RS512 CSR ...
%OPENSSL% req -new ^
  -batch ^
  -key "%RS512_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%RS512_CSR%" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -sha512
if errorlevel 1 (
    echo FEHLER: RS512 CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [7/9] Erzeuge PS512 Private Key und CSR ...
%OPENSSL% genpkey ^
  -algorithm RSA-PSS ^
  -pkeyopt rsa_keygen_bits:3072 ^
  -pkeyopt rsa_pss_keygen_md:sha512 ^
  -pkeyopt rsa_pss_keygen_mgf1_md:sha512 ^
  -pkeyopt rsa_pss_keygen_saltlen:64 ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%PS512_KEY%"
if errorlevel 1 (
    echo FEHLER: PS512 Key konnte nicht erzeugt werden.
    exit /b 1
)

%OPENSSL% req -new ^
  -batch ^
  -key "%PS512_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%PS512_CSR%" ^
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
echo [8/9] Erzeuge ES512 Private Key und CSR ...
%OPENSSL% genpkey ^
  -algorithm EC ^
  -pkeyopt ec_paramgen_curve:P-521 ^
  -pkeyopt ec_param_enc:named_curve ^
  -aes-256-cbc ^
  -pass pass:%KEYPASS% ^
  -out "%ES512_KEY%"
if errorlevel 1 (
    echo FEHLER: ES512 Key konnte nicht erzeugt werden.
    exit /b 1
)

%OPENSSL% req -new ^
  -batch ^
  -key "%ES512_KEY%" ^
  -passin pass:%KEYPASS% ^
  -out "%ES512_CSR%" ^
  -config "%TEMPLATE%" ^
  -reqexts req_ext ^
  -sha512
if errorlevel 1 (
    echo FEHLER: ES512 CSR konnte nicht erzeugt werden.
    exit /b 1
)

echo.
echo [9/9] Fertig.
echo Erfolgreich erstellt:
echo   %RS512_KEY%
echo   %RS512_CSR%
echo   %PS512_KEY%
echo   %PS512_CSR%
echo   %ES512_KEY%
echo   %ES512_CSR%
echo.
echo Verwendetes Template:
echo   %TEMPLATE%
echo.
echo Private-Key-Passwort: %KEYPASS%
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
set "VALUE=!VALUE: =_!"
endlocal & set "%~2=%VALUE%"
exit /b 0