# FGUARD ISO Builder — WSL2 Helper
# Run this from PowerShell as Administrator:
#   cd C:\Users\stelakis-pc\Projects\firewall-gui\build
#   .\run-build-wsl.ps1

$ProjectDir = "C:\Users\stelakis-pc\Projects\firewall-gui"
$BuildScript = "/mnt/c/Users/stelakis-pc/Projects/firewall-gui/build/build-iso.sh"

Write-Host ""
Write-Host "  FGUARD ISO Builder" -ForegroundColor Cyan
Write-Host "  ══════════════════════" -ForegroundColor Cyan
Write-Host ""

# Check WSL is available
try {
    $wslCheck = wsl --list --quiet 2>$null
} catch {
    Write-Host "[!] WSL2 not found. Install it first:" -ForegroundColor Red
    Write-Host "    wsl --install" -ForegroundColor Yellow
    exit 1
}

Write-Host "[→] Starting ISO build in WSL2..." -ForegroundColor Cyan
Write-Host "[!] This will take 15-30 minutes depending on internet speed." -ForegroundColor Yellow
Write-Host "[!] Do NOT close this window." -ForegroundColor Yellow
Write-Host ""

# Run build script in WSL2 as root
wsl -u root bash -c "
    # Works on both Debian and Ubuntu WSL
    if ! command -v apt-get &>/dev/null; then
        echo 'ERROR: Need Debian or Ubuntu WSL distribution'
        exit 1
    fi

    # Run the build
    chmod +x '$BuildScript'
    bash '$BuildScript'
"

if ($LASTEXITCODE -eq 0) {
    $IsoPath = "$ProjectDir\build\fguard.iso"
    if (Test-Path $IsoPath) {
        $IsoSize = (Get-Item $IsoPath).Length / 1GB
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║  ISO READY!                               ║" -ForegroundColor Green
        Write-Host "  ║                                           ║" -ForegroundColor Green
        Write-Host "  ║  $IsoPath" -ForegroundColor Green
        Write-Host "  ║  Size: $([math]::Round($IsoSize, 1)) GB                           ║" -ForegroundColor Green
        Write-Host "  ║                                           ║" -ForegroundColor Green
        Write-Host "  ║  Next: Open Hyper-V Manager               ║" -ForegroundColor Green
        Write-Host "  ║  Create VM → attach this ISO → Boot!      ║" -ForegroundColor Green
        Write-Host "  ╚══════���═══════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""

        # Ask to open folder
        $open = Read-Host "Open folder in Explorer? (y/n)"
        if ($open -eq "y") {
            explorer.exe "$ProjectDir\build"
        }
    }
} else {
    Write-Host ""
    Write-Host "[✗] Build failed. Check the output above for errors." -ForegroundColor Red
}
