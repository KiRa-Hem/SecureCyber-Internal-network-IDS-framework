# Npcap Verification Script
Write-Host "Checking Npcap installation..." -ForegroundColor Cyan

# Check registry
Write-Host "`n1. Checking Registry:" -ForegroundColor Yellow
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Npcap",
    "HKLM:\SOFTWARE\Npcap",
    "HKLM:\SOFTWARE\WOW6432Node\Npcap"
)

foreach ($path in $registryPaths) {
    Write-Host "  Checking: $path" -ForegroundColor Gray
    if (Test-Path $path) {
        Write-Host "    Found!" -ForegroundColor Green
        try {
            $version = (Get-ItemProperty -Path $path -Name "DisplayVersion" -ErrorAction SilentlyContinue).DisplayVersion
            if (-not $version) {
                $version = (Get-ItemProperty -Path $path -Name "Version" -ErrorAction SilentlyContinue).Version
            }
            if ($version) {
                Write-Host "    Version: $version" -ForegroundColor Green
            }
        } catch {
            Write-Host "    Could not determine version" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    Not found" -ForegroundColor Red
    }
}

# Check installation directory
Write-Host "`n2. Checking Installation Directory:" -ForegroundColor Yellow
$npcapPaths = @(
    "${env:ProgramFiles}\Npcap",
    "${env:ProgramFiles(x86)}\Npcap",
    "${env:ProgramW6432}\Npcap"
)

foreach ($path in $npcapPaths) {
    Write-Host "  Checking: $path" -ForegroundColor Gray
    if (Test-Path $path) {
        Write-Host "    Found!" -ForegroundColor Green
        # Check for npcap.exe
        $npcapExe = Join-Path $path "npcap.exe"
        if (Test-Path $npcapExe) {
            try {
                $version = (Get-Item $npcapExe).VersionInfo.FileVersion
                Write-Host "    Npcap.exe version: $version" -ForegroundColor Green
            } catch {
                Write-Host "    Could not determine version" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "    Not found" -ForegroundColor Red
    }
}

# Check service
Write-Host "`n3. Checking Service:" -ForegroundColor Yellow
try {
    $npcapService = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    if ($npcapService) {
        Write-Host "  Service found!" -ForegroundColor Green
        Write-Host "  Status: $($npcapService.Status)" -ForegroundColor Green
        Write-Host "  Display Name: $($npcapService.DisplayName)" -ForegroundColor Green
    } else {
        Write-Host "  Service not found" -ForegroundColor Red
    }
} catch {
    Write-Host "  Error checking service: $_" -ForegroundColor Red
}

# Check if Npcap is working with Scapy
Write-Host "`n4. Testing Npcap with Python:" -ForegroundColor Yellow
try {
    # Check if Python is available
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        Write-Host "  Python found: $($python.Source)" -ForegroundColor Green
        
        # Create a simple test script
        $testScript = @"
import sys
try:
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print('Found ' + str(len(interfaces)) + ' interfaces')
    for i, iface in enumerate(interfaces[:5]):  # Show first 5 interfaces
        print('  ' + str(i+1) + '. ' + str(iface))
    print('Npcap is working correctly with Scapy!')
except ImportError:
    print('Scapy not installed')
except Exception as e:
    print('Error: ' + str(e))
    print('Npcap might not be properly installed or configured')
"@
        
        # Run the test
        $result = python -c $testScript 2>&1
        if ($result -like "*Npcap is working correctly*") {
            Write-Host "  Npcap is working correctly!" -ForegroundColor Green
            Write-Host $result
        } else {
            Write-Host "  Npcap test failed:" -ForegroundColor Red
            Write-Host $result
        }
    } else {
        Write-Host "  Python not found" -ForegroundColor Red
    }
} catch {
    Write-Host "  Error testing Npcap: $_" -ForegroundColor Red
}

Write-Host "`nVerification complete." -ForegroundColor Cyan
Read-Host "Press Enter to exit"