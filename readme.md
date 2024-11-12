# DNS Security Monitoring System - ICANN 81 NextGen Presentation Demo

## Overview
This project demonstrates a real-time DNS monitoring system with machine learning-powered threat detection, developed for the ICANN 81 NextGen presentation. The system captures and analyzes DNS queries, providing insights into potential security threats and abnormal patterns in DNS traffic.

## Features
- Real-time DNS packet capture and analysis
- Machine learning-based domain categorization and risk assessment
- Web-based dashboard for live monitoring
- Rate limiting and IP blocking capabilities
- Suspicious pattern detection
- WebSocket-based real-time updates
- Domain analysis caching for improved performance

## Components
The project consists of three main components:

### 1. DNS Monitor (`dns.py`)
- Core monitoring system built with FastAPI and Scapy
- Captures and analyzes DNS packets in real-time
- Integrates with OpenAI's GPT for domain analysis
- Implements rate limiting and pattern-based threat detection

### 2. Attack Tester (`dns_attack_tester.py`)
- Testing utility to simulate various DNS-based attacks
- Helps demonstrate the system's detection capabilities
- Useful for security testing and demonstration purposes

### 3. Dashboard (`index.html`)
- Web-based interface for real-time monitoring
- Displays DNS queries, security alerts, and statistics
- Interactive controls for IP blocking/unblocking

## Prerequisites
- Python 3.8+
- OpenAI API key
- Required Python packages:
  ```
  fastapi
  uvicorn
  scapy
  openai
  python-dotenv
  ```

## Setup
1. Clone the repository
2. Create a `.env` file with your OpenAI API key:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Start the DNS monitor:
   ```bash
   sudo python dns.py
   ```
   Note: Requires sudo/admin privileges for packet capture

2. Open the dashboard:
   ```
   open index.html
   ```

3. (Optional) Run the attack tester:
   ```bash
   python dns_attack_tester.py
   ```

## API Endpoints
- WebSocket: `ws://localhost:8000/ws`
- Block IP: `POST /block_ip/{ip}`
- Unblock IP: `DELETE /unblock_ip/{ip}`

## Security Features
- Domain risk assessment using AI
- Pattern-based threat detection
- Rate limiting
- IP blocking
- Suspicious TLD monitoring
- DGA (Domain Generation Algorithm) detection

## Contributing
Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License
MIT License
=
