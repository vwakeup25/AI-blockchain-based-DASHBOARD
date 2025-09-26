# Synapse Sentinel: AI-Powered Blockchain-Based Security Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-19-blue.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116-green.svg)](https://fastapi.tiangolo.com/)

**Synapse Sentinel** is a sophisticated, real-time network security monitoring dashboard that leverages Artificial Intelligence and blockchain principles to provide a tamper-evident logging system. It actively sniffs network traffic, detects anomalies using a hybrid AI and rule-based approach, and presents the findings in a rich, interactive web interface.

## ✨ Key Features

- **Real-Time Traffic Analysis**: Captures and analyzes network packets in real-time without significant performance overhead.
- **AI-Powered Anomaly Detection**: Utilizes a hybrid system combining a Machine Learning model (River) and rule-based logic to detect various threats like DDoS attempts, suspicious host activity, and other network anomalies.
- **Blockchain-Inspired Secure Logging**: Each log entry is cryptographically hashed and chained to the previous one, creating a tamper-evident, blockchain-style ledger of security events.
- **Data Integrity and Confidentiality**: Log data is signed with Ed25519 keys for integrity and encrypted using Fernet (AES-128) to ensure confidentiality.
- **Threat Intelligence Integration**: Enriches IP data with GeoIP location, reverse DNS, and real-time reputation checks from **AbuseIPDB** to identify high-risk actors.
- **Interactive Dashboard**: A modern, responsive frontend built with React and Chart.js provides at-a-glance visualizations of network health, anomaly distributions, and live traffic rates.
- **Active Response System**: Allows security administrators to instantly block malicious IP addresses directly from the dashboard via dynamic firewall rule generation (`iptables` for Linux, `netsh` for Windows).
- **Comprehensive Reporting**: Features include detailed log filtering, pagination, and the ability to export security reports as a PDF.

## 🏛️ Project Architecture

The project is composed of three main services that work in concert:

1.  **Packet Sniffer (`sniffer.py`)**: A lightweight Scapy-based service that captures raw IP packets from a designated network interface and pushes them to a Redis message queue for processing.
2.  **Analysis Worker (`worker.py`)**: The core detection engine. This service consumes packets from Redis, performs analysis, and writes to the secure database. Its tasks include:
    -   Applying the ML model and rule-based checks.
    -   Enriching data with threat intelligence.
    -   Calculating hashes, signing data, and encrypting sensitive information.
    -   Storing the final, secure log entry in the database.
3.  **Backend API & Frontend (FastAPI & React)**:
    -   The **FastAPI** backend serves the data to the user interface, handles user authentication, and executes administrative actions like blocking IPs.
    -   The **React** frontend provides the interactive dashboard for data visualization and user interaction.

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Node.js v18+ and npm
- Redis (can be run easily via Docker)
- `libpcap` or `Npcap` for packet sniffing (`sudo apt-get install libpcap-dev` on Debian/Ubuntu, or install Npcap from the official website on Windows).

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/vwakeup25/AI-blockchain-based-DASHBOARD.git
    cd AI-blockchain-based-DASHBOARD
    ```

2.  **Start Redis:**
    The simplest way is to use Docker.
    ```bash
    docker run -d -p 6379:6379 --name redis-sentinel redis
    ```

3.  **Setup the Backend:**
    ```bash
    cd backend
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```
    **Generate Security Keys:**
    Run the key generation script to create your unique cryptographic keys.
    ```bash
    python gen_keys.py
    ```

4.  **Setup the Frontend:**
    ```bash
    cd ../frontend
    npm install
    ```

### Running the Application

You need to run the three components in separate terminals.

-   **Terminal 1: Start the Analysis Worker**
    ```bash
    cd backend
    source venv/bin/activate # Or venv\Scripts\activate
    python worker.py
    ```

-   **Terminal 2: Start the Packet Sniffer**
    > **Important:** You must run this script with administrator/root privileges.
    ```bash
    cd backend
    source venv/bin/activate # Or venv\Scripts\activate
    sudo python sniffer.py # On Linux/macOS
    # On Windows, open PowerShell as Administrator and run:
    # python sniffer.py
    ```
    *Note: The first time you run `sniffer.py`, it will list network interfaces. You must edit the `INTERFACE_TO_SNIFF` variable in the file to match your primary network interface (e.g., "Wi-Fi" or "Ethernet").*

-   **Terminal 3: Start the Backend API Server**
    ```bash
    cd backend
    source venv/bin/activate # Or venv\Scripts\activate
    uvicorn main:app --reload
    ```

-   **Terminal 4: Start the Frontend Development Server**
    ```bash
    cd frontend
    npm start
    ```

Once all services are running, open your browser and navigate to **http://localhost:3000**.

## 🛠️ Technologies Used

-   **Backend**: Python, FastAPI, Scapy, SQLAlchemy, River (ML), Redis
-   **Frontend**: React, Chart.js, Tailwind CSS, Framer Motion
-   **Database**: SQLite (default), easily configurable to PostgreSQL or others.
-   **Cryptography**: Ed25519 (for signing), Fernet (for encryption)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any bugs or feature requests.

## 📜 License

This project is licensed under the MIT License.
