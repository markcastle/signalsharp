@echo off
setlocal enabledelayedexpansion

echo SignalSharp Production Build Script
echo ==================================

:: Define variables
set SOLUTION_PATH=SignalSharp.sln
set CONFIGURATION=Release
set OUTPUT_PATH=.\build\output
set NUGET_OUTPUT_PATH=.\build\nuget
set TEST_RESULTS_PATH=.\build\test-results
set VERSION=1.0.0

:: Create output directories if they don't exist
if not exist "%OUTPUT_PATH%" (
    mkdir "%OUTPUT_PATH%"
    echo Created output directory: %OUTPUT_PATH%
)

if not exist "%NUGET_OUTPUT_PATH%" (
    mkdir "%NUGET_OUTPUT_PATH%"
    echo Created NuGet output directory: %NUGET_OUTPUT_PATH%
)

if not exist "%TEST_RESULTS_PATH%" (
    mkdir "%TEST_RESULTS_PATH%"
    echo Created test results directory: %TEST_RESULTS_PATH%
)

:: Check for dotnet CLI
where dotnet >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: dotnet CLI not found. Please install the .NET SDK.
    exit /b 1
)

:: Clean previous build
echo Cleaning previous build...
dotnet clean "%SOLUTION_PATH%" --configuration %CONFIGURATION%
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to clean solution.
    exit /b 1
)

:: Restore packages
echo Restoring NuGet packages...
dotnet restore "%SOLUTION_PATH%"
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to restore packages.
    exit /b 1
)

:: Build solution
echo Building solution in %CONFIGURATION% configuration...
dotnet build "%SOLUTION_PATH%" --configuration %CONFIGURATION% --no-restore
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to build solution.
    exit /b 1
)

:: Run tests
echo Running tests...
dotnet test "%SOLUTION_PATH%" --configuration %CONFIGURATION% --no-build --results-directory "%TEST_RESULTS_PATH%" --collect:"XPlat Code Coverage" --settings coverlet.runsettings
if %ERRORLEVEL% neq 0 (
    echo Error: Tests failed. Build aborted.
    exit /b 1
)

:: Publish projects
echo Publishing projects...
dotnet publish "%SOLUTION_PATH%" --configuration %CONFIGURATION% --output "%OUTPUT_PATH%" --no-build
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to publish projects.
    exit /b 1
)

:: Pack NuGet packages
echo Creating NuGet packages...
dotnet pack "%SOLUTION_PATH%" --configuration %CONFIGURATION% --output "%NUGET_OUTPUT_PATH%" --no-build --version-suffix %VERSION%
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to create NuGet packages.
    exit /b 1
)

:: Sign assemblies if needed (uncomment and configure if required)
:: echo Signing assemblies...
:: set PFX_PATH=path\to\your\certificate.pfx
:: set PFX_PASSWORD=your-password
:: for %%f in ("%OUTPUT_PATH%\*.dll") do (
::     signtool sign /f "%PFX_PATH%" /p "%PFX_PASSWORD%" /tr http://timestamp.digicert.com /td sha256 /fd sha256 "%%f"
:: )

:: Create a zip archive of the output
echo Creating distribution package...
set ZIP_PATH=.\build\SignalSharp-%VERSION%.zip
if exist "%ZIP_PATH%" del "%ZIP_PATH%"

:: Use PowerShell to create the zip file
powershell -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::CreateFromDirectory('%OUTPUT_PATH%', '%ZIP_PATH%')"
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to create distribution package.
    exit /b 1
)

echo Build completed successfully!
echo Output: %OUTPUT_PATH%
echo NuGet packages: %NUGET_OUTPUT_PATH%
echo Distribution package: %ZIP_PATH%

endlocal 