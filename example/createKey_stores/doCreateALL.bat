@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem =========================================================
rem Master-Script
rem - verarbeitet die unten konfigurierte Liste von Testfaellen
rem - nutzt je Testfall die Verzeichnisse .\<Testfallname>-<hash>
rem - ruft Script 1 und Script 2 auf
rem - fuehrt abschliessend alle *all-seal-certs-<hash>.pem zu
rem   .\all-seal-certs-<hash>.pem zusammen
rem
rem Parameter:
rem   --allCertsOnly
rem   --hash 256|512
rem =========================================================

rem =========================================================
rem KONFIGURATION DER TESTFAELLE
rem
rem Hier die Testfaelle anpassen:
rem Jeder Eintrag ist der Basisname ohne ".cnf"
rem
rem Beispiel:
rem   set "TEST_CASES=TC1 TC2 TC3 TC4 TC5"
rem   set "TEST_CASES=BankA BankB BankC"
rem   or use the CN as name:
rem   set "TEST_CASES=GlueckAuf-GmbH-1 GlueckAuf-GmbH-2 Red-Keys-GmbH-01 Red-Keys-GmbH-1 Red-Keys-GmbH-2 Red-Keys-GmbH-3 Sugar-Plum-GmbH-1 Sugar-Plum-GmbH-2"
rem =========================================================
set "TEST_CASES=TC1 TC2 TC3 TC4 TC5"

set "SCRIPT_DIR=%~dp0"
set "SCRIPT1=%SCRIPT_DIR%createKeysAndCSRs.bat"
set "SCRIPT2=%SCRIPT_DIR%createCertsAndStores.bat"
set "ALL_CERTS_ONLY=0"
set "HASH_BITS=512"
set "FINAL_ALL_CERTS="

:parse_args
if "%~1"=="" goto args_done

if /I "%~1"=="--allCertsOnly" (
    set "ALL_CERTS_ONLY=1"
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
echo Erwartet: --allCertsOnly --hash ^<256^|512^>
exit /b 1

:args_done

set "FINAL_ALL_CERTS=%CD%\all-seal-certs-%HASH_BITS%.pem"

echo.
echo [1/4] Pruefe Master-Voraussetzungen ...

if not exist "%SCRIPT1%" (
    echo FEHLER: Script 1 nicht gefunden: %SCRIPT1%
    exit /b 1
)
if not exist "%SCRIPT2%" (
    echo FEHLER: Script 2 nicht gefunden: %SCRIPT2%
    exit /b 1
)

for %%C in (%TEST_CASES%) do (
    if not exist "%SCRIPT_DIR%%%C.cnf" (
        echo FEHLER: Config-Datei nicht gefunden: %SCRIPT_DIR%%%C.cnf
        exit /b 1
    )
)

echo   OK: Skripte und CNF-Dateien gefunden.
echo   Hash: %HASH_BITS%

if "%ALL_CERTS_ONLY%"=="1" goto build_all_certs_only

echo.
echo [2/4] Erzeuge Material fuer konfigurierte Testfaelle ...

for %%C in (%TEST_CASES%) do (
    echo.
    echo ========================================
    echo Verarbeite Testfall %%C
    echo ========================================

    set "CASE_NAME=%%C"
    set "CASE_OUTDIR=%SCRIPT_DIR%%%C"

    echo.
    echo Starte Script 1 fuer %%C ...
    call "%SCRIPT1%" --outdir "!CASE_OUTDIR!" --cnf "%%C.cnf" --hash %HASH_BITS%
    if errorlevel 1 (
        echo FEHLER: Script 1 ist fuer %%C fehlgeschlagen.
        exit /b 1
    )

    echo.
    echo Starte Script 2 fuer %%C ...
    call "%SCRIPT2%" --outdir "!CASE_OUTDIR!" --hash %HASH_BITS%
    if errorlevel 1 (
        echo FEHLER: Script 2 ist fuer %%C fehlgeschlagen.
        exit /b 1
    )
)

echo.
echo [3/4] Fuehre alle *all-seal-certs-%HASH_BITS%.pem zusammen ...
goto concat_all_certs

:build_all_certs_only
echo.
echo [2/2] Fuehre nur alle vorhandenen *all-seal-certs-%HASH_BITS%.pem zusammen ...

:concat_all_certs
if exist "%FINAL_ALL_CERTS%" del /f /q "%FINAL_ALL_CERTS%" >nul 2>nul

set "FOUND_ANY=0"

for %%C in (%TEST_CASES%) do (
    set "CASE_OUTDIR=%SCRIPT_DIR%%%C-%HASH_BITS%"
    if exist "!CASE_OUTDIR!\*-all-seal-certs-%HASH_BITS%.pem" (
        for %%F in ("!CASE_OUTDIR!\*-all-seal-certs-%HASH_BITS%.pem") do (
            echo   Fuege hinzu: %%~fF
            type "%%~fF" >> "%FINAL_ALL_CERTS%"
            echo.>> "%FINAL_ALL_CERTS%"
            set "FOUND_ANY=1"
        )
    ) else (
        echo   HINWEIS: Kein *all-seal-certs-%HASH_BITS%.pem in !CASE_OUTDIR! gefunden.
    )
)

if "!FOUND_ANY!"=="0" (
    echo FEHLER: Es wurde keine *all-seal-certs-%HASH_BITS%.pem gefunden.
    exit /b 1
)

echo.
if "%ALL_CERTS_ONLY%"=="1" (
    echo Fertig.
    echo Erzeugt:
    echo   %FINAL_ALL_CERTS%
    exit /b 0
)

echo [4/4] Fertig.
echo Erzeugt:
echo   %FINAL_ALL_CERTS%
exit /b 0