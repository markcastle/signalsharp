# SignalSharp Production Build Script
# This script builds the SignalSharp solution for production

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

# Define variables
$solutionPath = "SignalSharp.sln"
$configuration = "Release"
$outputPath = ".\build\output"
$nugetOutputPath = ".\build\nuget"
$testResultsPath = ".\build\test-results"
$version = "1.0.0" # Update this as needed

# Create output directories if they don't exist
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath | Out-Null
    Write-Host "Created output directory: $outputPath"
}

if (-not (Test-Path $nugetOutputPath)) {
    New-Item -ItemType Directory -Path $nugetOutputPath | Out-Null
    Write-Host "Created NuGet output directory: $nugetOutputPath"
}

if (-not (Test-Path $testResultsPath)) {
    New-Item -ItemType Directory -Path $testResultsPath | Out-Null
    Write-Host "Created test results directory: $testResultsPath"
}

# Function to check if a command exists
function Test-CommandExists {
    param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {
        if (Get-Command $command) { return $true }
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $oldPreference
    }
}

# Check for required tools
if (-not (Test-CommandExists "dotnet")) {
    Write-Error "dotnet CLI not found. Please install the .NET SDK."
    exit 1
}

# Clean previous build
Write-Host "Cleaning previous build..." -ForegroundColor Cyan
dotnet clean $solutionPath --configuration $configuration

# Restore packages
Write-Host "Restoring NuGet packages..." -ForegroundColor Cyan
dotnet restore $solutionPath

# Build solution
Write-Host "Building solution in $configuration configuration..." -ForegroundColor Cyan
dotnet build $solutionPath --configuration $configuration --no-restore

# Run tests
Write-Host "Running tests..." -ForegroundColor Cyan
dotnet test $solutionPath --configuration $configuration --no-build --results-directory $testResultsPath --collect:"XPlat Code Coverage" --settings coverlet.runsettings

# Check if tests passed
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed. Build aborted."
    exit 1
}

# Publish projects
Write-Host "Publishing projects..." -ForegroundColor Cyan
dotnet publish $solutionPath --configuration $configuration --output $outputPath --no-build

# Pack NuGet packages
Write-Host "Creating NuGet packages..." -ForegroundColor Cyan
dotnet pack $solutionPath --configuration $configuration --output $nugetOutputPath --no-build --version-suffix $version

# Sign assemblies if needed (uncomment and configure if required)
# Write-Host "Signing assemblies..." -ForegroundColor Cyan
# $pfxPath = "path\to\your\certificate.pfx"
# $pfxPassword = "your-password"
# Get-ChildItem -Path $outputPath -Filter "*.dll" | ForEach-Object {
#     & signtool sign /f $pfxPath /p $pfxPassword /tr http://timestamp.digicert.com /td sha256 /fd sha256 $_.FullName
# }

# Create a zip archive of the output
Write-Host "Creating distribution package..." -ForegroundColor Cyan
$zipPath = ".\build\SignalSharp-$version.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipPath)

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Output: $outputPath" -ForegroundColor Green
Write-Host "NuGet packages: $nugetOutputPath" -ForegroundColor Green
Write-Host "Distribution package: $zipPath" -ForegroundColor Green 