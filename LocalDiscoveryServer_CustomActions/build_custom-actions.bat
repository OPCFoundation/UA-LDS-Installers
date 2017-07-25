@ECHO off
REM ****************************************************************************************************************
REM ** This script builds the LDS Installer Custom Actions.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

CALL "c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat"

set SRCDIR=%~dp0
set INSTALLDIR=%~dp0..\LDSBinaries
set GIT=C:\Program Files (x86)\Git\bin\git.exe
set SIGNTOOL=C:\Build\sign_output.bat

ECHO STEP 1) Building LDS Installer Custom Actions
cd %SRCDIR%
msbuild "ldsca.sln" /p:Configuration=Release 

ECHO STEP 2) Sign the Binaries
IF EXIST "%SIGNTOOL%" CALL "%SIGNTOOL%" %SRCDIR%Release\*.dll /sha1

ECHO STEP 3) Copy Outputs
XCOPY /Y /Q ".\Release\*.dll" "%INSTALLDIR%"

ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
ENDLOCAL