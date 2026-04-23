@echo off
setlocal

pushd "%~dp0" || (
    echo [!] Failed to enter script directory: "%~dp0"
    pause
    exit /b 1
)

echo Building ProcessInstrumentationCallback
echo ========================================

set "ASM_SOURCE=ProcessInstrumentationStub.asm"
set "OBJ_DIR=obj"
set "OUTPUT=ProcessInstrumentation.exe"

if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

if not exist "%ASM_SOURCE%" (
    echo [!] Missing file: %ASM_SOURCE%
    echo [!] Full path checked: "%CD%\%ASM_SOURCE%"
    goto :error
)

if not exist "ProcessInstrumentation.cpp" (
    echo [!] Missing file: ProcessInstrumentation.cpp
    goto :error
)

if not exist "main.cpp" (
    echo [!] Missing file: main.cpp
    goto :error
)

call :ensure_msvc_env

where ml64 >nul 2>nul || (
    echo [!] ml64 not found
    goto :error
)

where cl >nul 2>nul || (
    echo [!] cl not found
    goto :error
)

where link >nul 2>nul || (
    echo [!] link not found
    goto :error
)

echo Current dir: "%CD%"

echo [1/3] Assembling MASM x64 stub...
ml64 ^
    /c ^
    /Fo"%OBJ_DIR%\%ASM_SOURCE:.asm=.obj%" ^
    /Zi ^
    "%ASM_SOURCE%"

if errorlevel 1 (
    echo [!] Assembly failed
    goto :error
)
echo [+] Assembly complete: "%OBJ_DIR%\%ASM_SOURCE:.asm=.obj%"

echo [2/3] Compiling C++ sources...
cl ^
    /c ^
    /EHsc ^
    /O2 ^
    /Zi ^
    /MD ^
    /std:c++17 ^
    /I. ^
    /Fo"%OBJ_DIR%\\" ^
    "ProcessInstrumentation.cpp" ^
    "main.cpp"

if errorlevel 1 (
    echo [!] Compilation failed
    goto :error
)
echo [+] Compilation complete

echo [3/3] Linking executable...
link ^
    /NOLOGO ^
    /OUT:"%OUTPUT%" ^
    /SUBSYSTEM:CONSOLE ^
    /DEBUG ^
    /OPT:REF ^
    /OPT:ICF ^
    "%OBJ_DIR%\ProcessInstrumentationStub.obj" ^
    "%OBJ_DIR%\ProcessInstrumentation.obj" ^
    "%OBJ_DIR%\main.obj" ^
    ntdll.lib ^
    kernel32.lib

if errorlevel 1 (
    echo [!] Linking failed
    goto :error
)

echo ========================================
echo [+] Build successful: %OUTPUT%
echo ========================================
popd
pause
exit /b 0

:ensure_msvc_env
where cl >nul 2>nul && goto :eof

echo [i] MSVC tools not in PATH, trying to load vcvars64.bat...

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%I\VC\Auxiliary\Build\vcvars64.bat" (
            call "%%I\VC\Auxiliary\Build\vcvars64.bat" >nul
            goto :eof
        )
    )
)

for %%P in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) do (
    if exist %%~P (
        call %%~P >nul
        goto :eof
    )
)

goto :eof

:error
echo.
echo Build failed.
popd
pause
exit /b 1
