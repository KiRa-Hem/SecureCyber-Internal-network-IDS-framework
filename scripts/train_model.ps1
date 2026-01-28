# Enhanced IDS/IPS System - CICIDS XGBoost Training Script for Windows

param(
    [string]$InputFile = "",
    [string]$OutputDir = "",
    [switch]$PreprocessOnly,
    [switch]$RunEval
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$RED = [ConsoleColor]::Red
$GREEN = [ConsoleColor]::Green
$YELLOW = [ConsoleColor]::Yellow
$BLUE = [ConsoleColor]::Blue
$NC = [ConsoleColor]::White

function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

Write-ColorOutput $BLUE "=============================================="
Write-ColorOutput $BLUE "  Enhanced IDS/IPS System - CICIDS XGBoost"
Write-ColorOutput $BLUE "=============================================="

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$trainingDir = Join-Path $repoRoot "models\training_scripts"

$datasetPath = $InputFile
if (-not $datasetPath) {
    $datasetPath = Join-Path $trainingDir "data\raw\cicids\cic.csv"
}

if (-not $OutputDir) {
    $OutputDir = Join-Path $trainingDir "data\cic"
}

$modelDir = Join-Path $repoRoot "models\cic"
if (-not (Test-Path $modelDir)) {
    New-Item -ItemType Directory -Path $modelDir | Out-Null
}

if (-not (Test-Path "venv")) {
    Write-ColorOutput $RED "Error: Virtual environment not found."
    Write-ColorOutput $YELLOW "Please run setup_env.ps1 first."
    exit 1
}

Write-ColorOutput $BLUE "Activating virtual environment..."
& .\venv\Scripts\Activate.ps1

$env:PYTHONPATH = "$PWD\backend;$env:PYTHONPATH"

Set-Location $trainingDir

if (-not (Test-Path $datasetPath)) {
    Write-ColorOutput $RED "Error: Dataset not found at $datasetPath."
    Write-ColorOutput $YELLOW "Provide -InputFile or place the dataset at the default location."
    Set-Location $repoRoot
    exit 1
}
else {
    Write-ColorOutput $GREEN "Found dataset at $datasetPath"
}

Write-ColorOutput $BLUE "Preprocessing dataset..."
python preprocess_cic.py --input-file "$datasetPath" --output-dir "$OutputDir" --time-split --time-col timestamp
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to preprocess dataset."
    Set-Location $repoRoot
    exit 1
}

if ($PreprocessOnly) {
    Write-ColorOutput $GREEN "Dataset preprocessed successfully."
    Set-Location $repoRoot
    exit 0
}

Write-ColorOutput $BLUE "Training XGBoost model..."
python train_models.py --data-dir "$OutputDir" --model-dir "$modelDir"
if ($LASTEXITCODE -ne 0) {
    Write-ColorOutput $RED "Error: Failed to train model."
    Set-Location $repoRoot
    exit 1
}

if ($RunEval) {
    Write-ColorOutput $BLUE "Evaluating trained model..."
    python evaluate_models.py --data-dir "$OutputDir" --model-dir "$modelDir"
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput $RED "Error: Failed to evaluate model."
        Set-Location $repoRoot
        exit 1
    }
}

Set-Location $repoRoot

Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $GREEN "  Model training complete!"
Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $BLUE "Artifacts saved in models/cic:" 
Write-ColorOutput $BLUE "- models/cic/attack_classifier_xgb.json"
