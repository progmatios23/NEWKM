$ErrorActionPreference = "Stop"

Write-Host "Cleaning previous builds..."
Remove-Item -Path "x64", "Release", "Debug" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Building Driver (Release|x64)..."
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" Driver.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:detailed

# Check if build succeeded by looking for the file
$sysPath = "x64\Release\Driver.sys"
if (Test-Path $sysPath) {
    Write-Host "Build SUCCESS!" -ForegroundColor Green
    
    # Copy to safe location
    $dest = "..\Driver.sys"
    Copy-Item $sysPath $dest -Force
    Write-Host "Driver copied to: $dest" -ForegroundColor Cyan
}
else {
    Write-Host "Build FAILED or file was deleted by WDK." -ForegroundColor Red
}
