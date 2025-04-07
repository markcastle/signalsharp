# 🏗️ SignalSharp Build Scripts

This directory contains scripts for building the SignalSharp solution for production.

## 🔧 Prerequisites

- .NET SDK (compatible with .NET Standard 2.1)
- PowerShell 5.0 or higher (for PowerShell script)
- Windows 10 or higher (for batch script)

## 📜 Available Scripts

### 🔄 PowerShell Script (build.ps1)

The PowerShell script provides a comprehensive build process with detailed output and error handling.

```powershell
# Run the build script
.\build.ps1
```

### 🔄 Batch Script (build.bat)

The batch script provides similar functionality for environments where PowerShell is not available or preferred.

```batch
# Run the build script
build.bat
```

## 🚀 What the Scripts Do

Both scripts perform the following operations:

1. **🧹 Clean** the solution to remove any previous build artifacts
2. **📦 Restore** NuGet packages
3. **🔨 Build** the solution in Release configuration
4. **🧪 Run tests** and collect code coverage
5. **📤 Publish** the projects to the output directory
6. **📦 Pack** NuGet packages
7. **📦 Create** a distribution package (ZIP file)

## 📂 Output

The build process creates the following output:

- **📦 Build Output**: `.\build\output\` - Contains the published assemblies
- **📦 NuGet Packages**: `.\build\nuget\` - Contains the NuGet packages
- **📊 Test Results**: `.\build\test-results\` - Contains test results and code coverage reports
- **📦 Distribution Package**: `.\build\SignalSharp-{version}.zip` - A ZIP file containing the published assemblies

## ⚙️ Customization

### 🔢 Version

To change the version of the build, edit the `$version` variable in the PowerShell script or the `VERSION` variable in the batch script.

### 🔒 Assembly Signing

To sign the assemblies, uncomment and configure the assembly signing section in either script.

### 📊 Code Coverage

The code coverage settings are configured in the `coverlet.runsettings` file. Modify this file to change the code coverage settings.

## 🔍 Troubleshooting

### ❌ Common Issues

- **❌ dotnet CLI not found**: Ensure that the .NET SDK is installed and available in the PATH.
- **❌ Tests fail**: Fix the failing tests before proceeding with the build.
- **❌ Build fails**: Check the error messages for specific issues.

### ❓ Getting Help

If you encounter issues with the build scripts, please open an issue in the repository. 