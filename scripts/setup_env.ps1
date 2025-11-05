# Enhanced IDS/IPS System - Windows Setup Script
# This script sets up the development environment for the IDS/IPS system on Windows

param(
    [switch]$SkipDeps,
    [switch]$SkipDataset,
    [switch]$SkipTraining
)

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Colors for output
$RED = [ConsoleColor]::Red
$GREEN = [ConsoleColor]::Green
$YELLOW = [ConsoleColor]::Yellow
$BLUE = [ConsoleColor]::Blue
$NC = [ConsoleColor]::White

# Function to print colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

# Function to check if command exists
function Test-Command($command) {
    return [bool](Get-Command $command -ErrorAction SilentlyContinue)
}

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-ColorOutput $BLUE "=============================================="
Write-ColorOutput $BLUE "  Enhanced IDS/IPS System - Windows Setup"
Write-ColorOutput $BLUE "=============================================="

# Check if running as Administrator
if (-not (Test-Administrator)) {
    Write-ColorOutput $YELLOW "Warning: Not running as Administrator. Some features may not work properly."
    Write-ColorOutput $YELLOW "Packet capture may require Administrator privileges."
}

# Check Python version
Write-ColorOutput $BLUE "Checking Python installation..."
if (-not (Test-Command python)) {
    Write-ColorOutput $RED "Error: Python is not installed."
    Write-ColorOutput $YELLOW "Please install Python 3.10 or higher from https://python.org"
    Read-Host "Press Enter to exit"
    exit 1
}

$pythonVersion = python --version 2>&1
Write-ColorOutput $GREEN "Python found: $pythonVersion"

# Check Git
Write-ColorOutput $BLUE "Checking Git installation..."
if (-not (Test-Command git)) {
    Write-ColorOutput $RED "Error: Git is not installed."
    Write-ColorOutput $YELLOW "Please install Git from https://git-scm.com/download/win"
    Read-Host "Press Enter to exit"
    exit 1
}

$gitVersion = git --version
Write-ColorOutput $GREEN "Git found: $gitVersion"

# Create virtual environment
Write-ColorOutput $BLUE "Creating Python virtual environment..."
if (Test-Path "venv") {
    Write-ColorOutput $YELLOW "Virtual environment already exists. Removing..."
    
    # Try to remove the virtual environment
    try {
        Remove-Item -Path "venv" -Recurse -Force -ErrorAction Stop
    } catch {
        Write-ColorOutput $RED "Error removing virtual environment: $_"
        Write-ColorOutput $YELLOW "Please run .\scripts\clean_venv.ps1 to clean up the virtual environment."
        Read-Host "Press Enter to exit"
        exit 1
    }
}

python -m venv venv
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to create virtual environment."
    Read-Host "Press Enter to exit"
    exit 1
}

# Activate virtual environment
Write-ColorOutput $BLUE "Activating virtual environment..."
& .\venv\Scripts\Activate.ps1

# Upgrade pip
Write-ColorOutput $BLUE "Upgrading pip..."
python -m pip install --upgrade pip

# Install requirements
Write-ColorOutput $BLUE "Installing Python dependencies..."
pip install -r backend\requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to install dependencies."
    Read-Host "Press Enter to exit"
    exit 1
}

# Install matplotlib for ML training
Write-Host "Installing matplotlib for data visualization..." -ForegroundColor Yellow
pip install matplotlib>=3.7.0
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Failed to install matplotlib. ML training may not work properly." -ForegroundColor Red
}

# Create necessary directories
Write-ColorOutput $BLUE "Creating directories..."
if (-not (Test-Path "backend\data")) { New-Item -ItemType Directory -Path "backend\data" | Out-Null }
if (-not (Test-Path "backend\logs")) { New-Item -ItemType Directory -Path "backend\logs" | Out-Null }
if (-not (Test-Path "models")) { New-Item -ItemType Directory -Path "models" | Out-Null }
if (-not (Test-Path "models\training_scripts")) { New-Item -ItemType Directory -Path "models\training_scripts" | Out-Null }
if (-not (Test-Path "models\training_scripts\data")) { New-Item -ItemType Directory -Path "models\training_scripts\data" | Out-Null }
if (-not (Test-Path "monitoring")) { New-Item -ItemType Directory -Path "monitoring" | Out-Null }
if (-not (Test-Path "scripts")) { New-Item -ItemType Directory -Path "scripts" | Out-Null }

# Setup environment file
if (-not (Test-Path "backend\.env")) {
    Write-ColorOutput $BLUE "Creating environment file..."
    Copy-Item "backend\.env.example" "backend\.env"
    Write-ColorOutput $GREEN "Environment file created at backend\.env"
    Write-ColorOutput $YELLOW "Please edit backend\.env to match your configuration"
} else {
    Write-ColorOutput $GREEN "Environment file already exists"
}

# Set environment variables for current session
$env:PYTHONPATH = "$PWD\backend;$env:PYTHONPATH"
$env:APP_HOST = "localhost"
$env:APP_PORT = "8000"
Write-ColorOutput $GREEN "Environment variables set for current session"

# Check for Npcap
Write-ColorOutput $BLUE "Checking Npcap installation..."
$npcapInstalled = $false
$npcapVersion = ""

# Try multiple registry locations
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Npcap",
    "HKLM:\SOFTWARE\Npcap",
    "HKLM:\SOFTWARE\WOW6432Node\Npcap"
)

foreach ($path in $registryPaths) {
    if (Test-Path $path) {
        $npcapInstalled = $true
        try {
            $npcapVersion = (Get-ItemProperty -Path $path -Name "DisplayVersion" -ErrorAction SilentlyContinue).DisplayVersion
            if (-not $npcapVersion) {
                $npcapVersion = (Get-ItemProperty -Path $path -Name "Version" -ErrorAction SilentlyContinue).Version
            }
            if ($npcapVersion) {
                break
            }
        } catch {
            # Continue to next path if this one fails
        }
    }
}

# Check installation directory as fallback
if (-not $npcapInstalled) {
    $npcapPaths = @(
        "${env:ProgramFiles}\Npcap",
        "${env:ProgramFiles(x86)}\Npcap",
        "${env:ProgramW6432}\Npcap"
    )
    
    foreach ($path in $npcapPaths) {
        if (Test-Path $path) {
            $npcapInstalled = $true
            # Try to get version from npcap.exe
            $npcapExe = Join-Path $path "npcap.exe"
            if (Test-Path $npcapExe) {
                try {
                    $npcapVersion = (Get-Item $npcapExe).VersionInfo.FileVersion
                } catch {
                    $npcapVersion = "Unknown"
                }
            }
            break
        }
    }
}

# Check if Npcap service is running
if (-not $npcapInstalled) {
    try {
        $npcapService = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
        if ($npcapService -and $npcapService.Status -eq "Running") {
            $npcapInstalled = $true
            $npcapVersion = "Service running (version unknown)"
        }
    } catch {
        # Service not found or not accessible
    }
}

if ($npcapInstalled) {
    if ($npcapVersion) {
        Write-ColorOutput $GREEN "Npcap found (version: $npcapVersion)"
    } else {
        Write-ColorOutput $GREEN "Npcap found (version unknown)"
    }
} else {
    Write-ColorOutput $YELLOW "Npcap is not installed or not detected."
    Write-ColorOutput $YELLOW "Please install Npcap from https://nmap.org/npcap/"
    Write-ColorOutput $YELLOW "Make sure to install with 'WinPcap API-compatible Mode'"
    
    $installNpcap = Read-Host "Install Npcap now? (y/n)"
    if ($installNpcap -eq 'y') {
        Start-Process "https://nmap.org/npcap/"
        Write-ColorOutput $BLUE "Please download and install Npcap, then restart this script."
        Write-ColorOutput $YELLOW "Important: Select 'WinPcap API-compatible Mode' during installation."
        Read-Host "Press Enter to exit"
        exit 0
    }
}

# Check for Redis
Write-ColorOutput $BLUE "Checking Redis installation..."
if (-not (Test-Command redis-server)) {
    Write-ColorOutput $YELLOW "Redis is not installed or not in PATH."
    Write-ColorOutput $YELLOW "Please install Redis for Windows from https://github.com/microsoftarchive/redis/releases"
    Write-ColorOutput $YELLOW "Note: Redis is optional for the demo mode."
    $installRedis = Read-Host "Install Redis now? (y/n)"
    if ($installRedis -eq 'y') {
        Start-Process "https://github.com/microsoftarchive/redis/releases"
        Write-ColorOutput $BLUE "Please download and install Redis, then restart this script."
        Read-Host "Press Enter to exit"
        exit 0
    }
} else {
    Write-ColorOutput $GREEN "Redis found"
}

# Check for MongoDB (Note: MongoDB Atlas is cloud-based, so we don't need local installation)
Write-ColorOutput $BLUE "MongoDB Atlas connection will be used."
Write-ColorOutput $YELLOW "Make sure your IP address is whitelisted in MongoDB Atlas."

# Prepare dataset
if (-not $SkipDataset) {
    $prepareData = Read-Host "Download and prepare KDD dataset? (y/n)"
    if ($prepareData -eq 'y') {
        Write-ColorOutput $BLUE "Preparing dataset..."
        
        # Define dataset path and URL
        $datasetPath = "models\training_scripts\data\kddcup.data_10_percent"
        $datasetUrl = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
        
        # Check if dataset already exists
        if (-not (Test-Path $datasetPath)) {
            Write-Host "KDD dataset not found. Attempting to download..." -ForegroundColor Yellow
            
            try {
                # Create data directory if needed
                $dataDir = Split-Path $datasetPath -Parent
                if (-not (Test-Path $dataDir)) { 
                    New-Item -ItemType Directory -Path $dataDir | Out-Null 
                }
                
                # Download and extract
                Invoke-WebRequest -Uri $datasetUrl -OutFile "$datasetPath.gz"
                
                # Extract gz file (Windows compatible method)
                $gzipPath = "$datasetPath.gz"
                $outputPath = $datasetPath
                
                # Use .NET GZipStream for extraction
                try {
                    $inputStream = New-Object System.IO.FileStream($gzipPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
                    $outputStream = New-Object System.IO.FileStream($outputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                    $gzipStream = New-Object System.IO.Compression.GZipStream($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
                    
                    $buffer = New-Object byte[](1024)
                    while (($count = $gzipStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $outputStream.Write($buffer, 0, $count)
                    }
                    
                    $gzipStream.Close()
                    $outputStream.Close()
                    $inputStream.Close()
                    
                    Remove-Item $gzipPath -Force
                    Write-Host "Dataset downloaded and extracted successfully." -ForegroundColor Green
                }
                catch {
                    Write-Host "Extraction failed: $_" -ForegroundColor Red
                    # Clean up
                    if ($inputStream) { $inputStream.Close() }
                    if ($outputStream) { $outputStream.Close() }
                    if ($gzipStream) { $gzipStream.Close() }
                    throw
                }
            }
            catch {
                Write-Host "Download failed: $_" -ForegroundColor Red
                Write-Host "Please manually download kddcup.data_10_percent_corrected and place it in:" -ForegroundColor Yellow
                Write-Host "$dataDir" -ForegroundColor Cyan
                Write-Host "Then rename it to 'kddcup.data_10_percent'" -ForegroundColor Yellow
                exit 1
            }
        }
        else {
            Write-Host "KDD dataset found at $datasetPath" -ForegroundColor Green
        }
        
        # Run preprocessing
        Set-Location models\training_scripts
        Write-Host "Running preprocessing script..." -ForegroundColor Yellow
        python preprocess_kdd.py
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Preprocessing failed. Continuing with raw dataset." -ForegroundColor Red
        }
        Set-Location ..\..
        
        Write-ColorOutput $GREEN "Dataset preparation complete"
    }
}

# Train models
if (-not $SkipTraining) {
    $trainModels = Read-Host "Train ML models? (y/n)"
    if ($trainModels -eq 'y') {
        Write-ColorOutput $BLUE "Training ML models..."
        Set-Location models\training_scripts
        python train_models.py
        Set-Location ..\..
        Write-ColorOutput $GREEN "ML models trained successfully"
    }
}

Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $GREEN "  Enhanced IDS/IPS System setup complete!"
Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $BLUE "Next steps:"
Write-ColorOutput $BLUE "1. Edit backend\.env to match your configuration"
Write-ColorOutput $BLUE "2. Activate the virtual environment: .\venv\Scripts\Activate.ps1"
Write-ColorOutput $BLUE "3. Start Redis (optional): redis-server"
Write-ColorOutput $BLUE "4. Run the demo: .\scripts\run_demo.ps1"
Write-ColorOutput $BLUE "5. Open browser to http://localhost:8000"

Read-Host "Press Enter to exit"