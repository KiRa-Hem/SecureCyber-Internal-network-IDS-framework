# SOC IDS Backend

This is the backend for the SOC (Security Operations Center) Intrusion Detection System (IDS) dashboard. It provides real-time attack detection and mitigation capabilities.

## Features

- Real-time attack detection using rule-based signatures, DDoS detection, and machine learning
- WebSocket communication with the frontend for real-time updates
- Mitigation actions including IP blocking and node isolation
- Event correlation to identify complex attack patterns
- RESTful API for management and monitoring
- Docker support for easy deployment

## Architecture

The backend consists of the following components:

1. **FastAPI Web Server**: Handles HTTP requests and WebSocket connections
2. **Sensor Workers**: Simulate network sensors at different locations (edge, internal)
3. **Detectors**: Implement different detection methods:
   - Rule-based detection for SQL injection, XSS, command injection, etc.
   - DDoS detection based on request rate
   - Machine learning-based anomaly detection
4. **Correlation Engine**: Correlates events from multiple sensors
5. **Mitigation Engine**: Implements blocking and isolation actions
6. **Database**: SQLite for storing alerts and mitigation actions

## Quick Start

### Prerequisites

- Python 3.10+
- Docker and Docker Compose (optional)

### Running with Docker

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd soc-ids-backend