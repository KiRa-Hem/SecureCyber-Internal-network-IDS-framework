# Enhanced IDS/IPS System - Model Training Script for Windows
# This script trains the ML models for the IDS/IPS system

param(
    [switch]$DownloadOnly,
    [switch]$PreprocessOnly
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

Write-ColorOutput $BLUE "=============================================="
Write-ColorOutput $BLUE "  Enhanced IDS/IPS System - Model Training"
Write-ColorOutput $BLUE "=============================================="

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-ColorOutput $RED "Error: Virtual environment not found."
    Write-ColorOutput $YELLOW "Please run setup_env.ps1 first."
    Read-Host "Press Enter to exit"
    exit 1
}

# Activate virtual environment
Write-ColorOutput $BLUE "Activating virtual environment..."
& .\venv\Scripts\Activate.ps1

# Set environment variables for current session
$env:PYTHONPATH = "$PWD\backend;$env:PYTHONPATH"

# Change to training scripts directory
Set-Location models\training_scripts

# Download dataset
Write-ColorOutput $BLUE "Downloading KDD dataset..."
python download_kdd.py
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to download dataset."
    Set-Location ..\..
    Read-Host "Press Enter to exit"
    exit 1
}

if ($DownloadOnly) {
    Write-ColorOutput $GREEN "Dataset downloaded successfully."
    Set-Location ..\..
    Read-Host "Press Enter to exit"
    exit 0
}

# Preprocess dataset
Write-ColorOutput $BLUE "Preprocessing dataset..."
python preprocess_kdd.py
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to preprocess dataset."
    Set-Location ..\..
    Read-Host "Press Enter to exit"
    exit 1
}

if ($PreprocessOnly) {
    Write-ColorOutput $GREEN "Dataset preprocessed successfully."
    Set-Location ..\..
    Read-Host "Press Enter to exit"
    exit 0
}

# Train models
Write-ColorOutput $BLUE "Training ML models..."
python train_models.py
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to train models."
    Set-Location ..\..
    Read-Host "Press Enter to exit"
    exit 1
}

# Return to project root
Set-Location ..\..

Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $GREEN "  Model training complete!"
Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $BLUE "Models saved in the models directory:"
Write-ColorOutput $BLUE "- models/attack_classifier_rf.pkl"
Write-ColorOutput $BLUE "- models/attack_classifier_dnn.pth"

Read-Host "Press Enter to exit"