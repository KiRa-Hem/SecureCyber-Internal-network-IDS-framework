# Enhanced IDS/IPS System - Demo Script for Windows
# This script runs a demo of the IDS/IPS system

param(
    [switch]$NoBrowser
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

Write-ColorOutput $BLUE "=============================================="
Write-ColorOutput $BLUE "  Enhanced IDS/IPS System - Demo Mode"
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
$env:APP_HOST = "localhost"
$env:APP_PORT = "8000"

# Check if Redis is running
Write-ColorOutput $BLUE "Checking Redis status..."
$redisRunning = $false
try {
    $redisStatus = redis-cli ping
    if ($redisStatus -eq "PONG") {
        Write-ColorOutput $GREEN "Redis is running"
        $redisRunning = $true
    } else {
        throw "Redis not responding"
    }
} catch {
    Write-ColorOutput $YELLOW "Redis is not running or not installed."
    Write-ColorOutput $YELLOW "The demo will run without Redis."
}

# Start the backend server
Write-ColorOutput $BLUE "Starting the backend server..."
$backendProcess = Start-Process -FilePath "python" -ArgumentList "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload" -WorkingDirectory "$PWD\backend" -NoNewWindow -PassThru
Write-ColorOutput $YELLOW "Waiting for backend server to start..."
Start-Sleep -Seconds 5

# Start the traffic simulator
Write-ColorOutput $BLUE "Starting the traffic simulator..."
$simulatorProcess = Start-Process -FilePath "python" -ArgumentList "scripts\traffic_simulator.py" -NoNewWindow -PassThru
Write-ColorOutput $YELLOW "Traffic simulator started"

# Open browser
if (-not $NoBrowser) {
    Write-ColorOutput $BLUE "Opening browser..."
    Start-Process "http://localhost:8000"
}

Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $GREEN "  Demo is running!"
Write-ColorOutput $GREEN "=============================================="
Write-ColorOutput $BLUE "Backend server: http://localhost:8000"
Write-ColorOutput $BLUE "API documentation: http://localhost:8000/docs"
Write-ColorOutput $BLUE "Dashboard: http://localhost:8000"
Write-ColorOutput $BLUE "Demo credentials are configured via DEMO_LOGIN_USERNAME / DEMO_LOGIN_PASSWORD"
Write-ColorOutput $YELLOW "Press Ctrl+C in the terminal windows to stop the services"

# Wait for user input to stop the demo
Read-Host "Press Enter to stop the demo"

# Stop processes
Write-ColorOutput $YELLOW "Stopping services..."
if ($backendProcess) {
    Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
}
if ($simulatorProcess) {
    Stop-Process -Id $simulatorProcess.Id -Force -ErrorAction SilentlyContinue
}

Write-ColorOutput $GREEN "Demo stopped."
