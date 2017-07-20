@ECHO off
REM ****************************************************************************************************************
REM ** This script builds the dummy LDS.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

set SRCDIR=%~dp0
set INSTALLDIR=%~dp0..\LDSBinaries\dummys
set GIT=C:\Program Files (x86)\Git\bin\git.exe
set SIGNTOOL=C:\Build\sign_output.bat

ECHO STEP 1) Deleting Output Directories
IF EXIST %INSTALLDIR%\bin rmdir /s /q %INSTALLDIR%\bin
IF EXIST %INSTALLDIR%\obj rmdir /s /q %INSTALLDIR%\obj

ECHO STEP 2) Building Dummy LDS
cd %SRCDIR%
msbuild "LocalDiscoveryServer_Dummy.sln" /p:Configuration=Release 

ECHO STEP 3) Sign the Binaries
IF EXIST "%SIGNTOOL%" CALL "%SIGNTOOL%" %SRCDIR%Release\*.exe /sha1

ECHO STEP 4) Copy Outputs
XCOPY /Y /Q ".\Release\*.exe" "%INSTALLDIR%"
XCOPY /Y /Q "..\..\Misc-Tools\bin\*.exe" "%INSTALLDIR%"

ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
ENDLOCAL