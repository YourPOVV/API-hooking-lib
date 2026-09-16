@echo off
setlocal

set "ROOT=%~dp0"
set "BUILD=%ROOT%build"

if not exist "%BUILD%" mkdir "%BUILD%"

if not defined DevEnvDir (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "%VSWHERE%" (
        for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
    )
    if not defined VSROOT (
        for %%p in (
            "C:\Program Files\Microsoft Visual Studio\18\Community"
            "C:\Program Files\Microsoft Visual Studio\2022\Community"
            "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
            "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
        ) do (
            if exist "%%~p\VC\Auxiliary\Build\vcvars64.bat" set "VSROOT=%%~p"
        )
    )
)

if not defined DevEnvDir (
    if not defined VSROOT (
        echo Visual Studio C++ tools not found. Install the "Desktop development with C++" workload.
        pause
        exit /b 1
    )
    call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul
)

cl /nologo /std:c++17 /EHsc /utf-8 /W4 /I"%ROOT%include" ^
    "%ROOT%tools\test.cpp" "%ROOT%src\lde.cpp" ^
    /Fo"%BUILD%\\" /Fe:"%BUILD%\hook-test.exe"

if errorlevel 1 (
    echo Test build failed.
    pause
    exit /b 1
)

"%BUILD%\hook-test.exe"
if errorlevel 1 (
    echo Tests failed.
    pause
    exit /b 1
)

cl /nologo /std:c++17 /O2 /EHsc /utf-8 /W4 /DUNICODE /D_UNICODE /I"%ROOT%include" ^
    "%ROOT%src\main.cpp" "%ROOT%src\hook.cpp" ^
    "%ROOT%src\lde.cpp" "%ROOT%src\log.cpp" ^
    /Fo"%BUILD%\\" /Fe:"%BUILD%\hook-demo.exe"

if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo %BUILD%\hook-demo.exe