# Enhanced IDS/IPS System - Clean Virtual Environment Script
# This script properly removes the virtual environment

# Colors for output
$RED = [ConsoleColor]::Red
$GREEN = [ConsoleColor]::Green
$YELLOW = [ConsoleColor]::Yellow
$BLUE = [ConsoleColor]::Blue

# Function to print colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

Write-ColorOutput $BLUE "=============================================="
Write-ColorOutput $BLUE "  Enhanced IDS/IPS System - Clean Virtual Environment"
Write-ColorOutput $BLUE "=============================================="

# Check if virtual environment exists
if (Test-Path "venv") {
    Write-ColorOutput $YELLOW "Virtual environment found. Removing..."
    
    try {
        # Try to remove the virtual environment
        Remove-Item -Path "venv" -Recurse -Force -ErrorAction Stop
        Write-ColorOutput $GREEN "Virtual environment removed successfully."
    } catch {
        Write-ColorOutput $RED "Error removing virtual environment: $_"
        Write-ColorOutput $YELLOW "Trying to remove with administrator privileges..."
        
        # Try to run as administrator
        $scriptPath = Join-Path $PWD "scripts\clean_venv_admin.ps1"
        $scriptContent = @"
Remove-Item -Path "$PWD\venv" -Recurse -Force
"@
        
        $scriptContent | Out-File -FilePath $scriptPath -Force
        
        try {
            Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", $scriptPath -Verb RunAs -Wait
            Remove-Item -Path $scriptPath -Force
            Write-ColorOutput $GREEN "Virtual environment removed successfully with administrator privileges."
        } catch {
            Write-ColorOutput $RED "Failed to remove virtual environment even with administrator privileges."
            Write-ColorOutput $YELLOW "Please manually delete the 'venv' folder and try again."
        }
    }
} else {
    Write-ColorOutput $GREEN "No virtual environment found."
}

Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $GREEN "  Clean complete!"
Write-ColorOutput $GREEN "=============================================="

Read-Host "Press Enter to exit"