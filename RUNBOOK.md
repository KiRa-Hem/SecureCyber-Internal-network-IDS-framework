# Enhanced IDS/IPS System - Windows Runbook

This runbook provides step-by-step instructions for deploying and running the Enhanced IDS/IPS System on Windows with MongoDB Atlas.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Demo Mode](#demo-mode)
4. [Production Deployment](#production-deployment)
5. [Monitoring and Maintenance](#monitoring-and-maintenance)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)

## System Requirements

### Minimum Requirements

- **CPU**: 2 cores
- **RAM**: 4 GB
- **Storage**: 20 GB
- **OS**: Windows 10 or Windows Server 2019+
- **Python**: 3.10+
- **Network**: Ethernet or Wi-Fi adapter
- **Internet Connection**: For MongoDB Atlas connection

### Recommended Requirements

- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Storage**: 50+ GB SSD
- **OS**: Windows 10/11 or Windows Server 2022+
- **Python**: 3.10+
- **Network**: Dedicated network interface for monitoring

## Installation

### Step 1: Install Python 3.10+

1. Download Python 3.10+ from [python.org](https://python.org)
2. Run the installer
3. **Important**: Check "Add Python to PATH"
4. Click "Install Now"
5. Wait for installation to complete
6. Verify installation:
   ```cmd
   python --version