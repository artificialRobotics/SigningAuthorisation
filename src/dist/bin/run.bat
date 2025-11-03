@echo off
setlocal ENABLEEXTENSIONS
set "BASEDIR=%~dp0.."
set "JAVA_EXE=%BASEDIR%\jre\bin\java.exe"
if not exist "%JAVA_EXE%" set "JAVA_EXE=java"

if not exist "%BASEDIR%\logs" mkdir "%BASEDIR%\logs"

set "JAVA_OPTS=-Dfile.encoding=UTF-8 -Xms128m -Xmx512m"
set "APP_JAR=%BASEDIR%\lib\signing-authorisation-cli.jar"

"%JAVA_EXE%" %JAVA_OPTS% -jar "%APP_JAR%" %* 1>>"%BASEDIR%\logs\stdout.log" 2>>"%BASEDIR%\logs\stderr.log"
set "RC=%ERRORLEVEL%"
echo Exit-Code: %RC%
endlocal & exit /b %RC%
