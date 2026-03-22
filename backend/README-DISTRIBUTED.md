# Distributed Vulnerability Assessment and Penetration Testing (VAPT) System

A revolutionary distributed scanning architecture that deploys intelligent agents across networks for scalable, efficient, and accurate vulnerability detection with real-time exploit validation.

## 🏗️ Architecture Overview

### Core Components

1. **Central Orchestration Engine** (`orchestrator/orchestrator.py`)
   - Manages distributed scanning agents
   - Intelligent task distribution and load balancing
   - Real-time monitoring and adaptive scheduling
   - Centralized result aggregation and reporting

2. **Scanning Agents** (`agents/scanning_agent.py`)
   - Autonomous network scanning units
   - Local vulnerability detection and validation
   - Real-time communication with orchestrator
   - Adaptive scanning based on network conditions

3. **Deployment Tools** (`deploy_agent.py`)
   - Automated agent deployment to remote systems
   - Bulk deployment capabilities
   - Configuration management

4. **Monitoring Dashboard** (`dashboard.html`)
   - Real-time system monitoring
   - Job management interface
   - Vulnerability prioritization display

## 🚀 Key Innovations

### 1. Distributed Scanning Agents
- **Scalability**: Deploy agents across multiple network segments
- **Efficiency**: Parallel scanning reduces total scan time
- **Resilience**: System continues operating if individual agents fail

### 2. Intelligent Orchestration
- **Smart Task Assignment**: Agents assigned based on network proximity and capabilities
- **Load Balancing**: Work distributed evenly across available agents
- **Adaptive Scheduling**: Tasks reassigned if agents become unavailable

### 3. Exploit Validation Engine
- **Real Risk Assessment**: Confirms vulnerabilities are actually exploitable
- **False Positive Elimination**: Reduces alert fatigue
- **Safe Testing**: Controlled proof-of-concept exploits

### 4. Centralized Intelligence
- **Result Aggregation**: Combines findings from all agents
- **Risk Prioritization**: Focuses on critical vulnerabilities
- **Comprehensive Reporting**: Unified view of network security posture

## 📋 Prerequisites

### System Requirements
- Python 3.8+
- Network connectivity between orchestrator and agents
- Administrative access for agent deployment

### Optional Tools (enhance scanning capabilities)
```bash
# Linux/macOS
sudo apt-get install nmap rustscan nuclei nikto whatweb httpx sqlmap

# Or using package managers
# macOS: brew install nmap nuclei nikto
# Windows: choco install nmap
```

## 🛠️ Installation

### 1. Install Dependencies
```bash
pip install -r requirements-distributed.txt
```

### 2. Start the Orchestrator
```bash
cd orchestrator
python orchestrator.py
```

The orchestrator will start on `http://localhost:8000`

### 3. Deploy Scanning Agents

#### Option A: Manual Deployment
```bash
# On each target system
python agents/scanning_agent.py --orchestrator http://your-orchestrator:8000
```

#### Option B: Automated Deployment
```bash
# Create deployment package
python deploy_agent.py --create-package

# Deploy to single host
python deploy_agent.py --deploy-to user@192.168.1.100 --key-file ~/.ssh/id_rsa

# Bulk deployment
python deploy_agent.py --bulk-deploy targets.json
```

Example `targets.json`:
```json
[
    {
        "host": "192.168.1.100",
        "user": "admin",
        "key_file": "/path/to/ssh/key"
    },
    {
        "host": "192.168.1.101",
        "user": "root",
        "password": "securepass"
    }
]
```

## 🎯 Usage

### 1. Access the Dashboard
Open `dashboard.html` in your web browser or serve it via a web server.

### 2. Create a Scan Job
1. Enter a job name
2. Specify targets (IP addresses, hostnames, CIDR ranges)
3. Select scan types:
   - **Port Scanning**: Discover open ports
   - **Service Detection**: Identify running services
   - **Vulnerability Scanning**: Find known vulnerabilities

### 3. Monitor Progress
- Real-time agent status
- Task completion progress
- System load distribution
- Vulnerability findings

### 4. Review Results
- Prioritized vulnerability list
- Detailed scan results per target
- Exploit validation status

## 🔧 Configuration

### Orchestrator Configuration
The orchestrator automatically discovers agents and assigns tasks. Key settings:

- **Heartbeat Interval**: 30 seconds (configurable)
- **Task Timeout**: 5 minutes per target
- **Agent Health Check**: Automatic removal of stale agents

### Agent Configuration
Agents auto-detect capabilities and network information:

- **Supported Tools**: nmap, nuclei, nikto, sqlmap, etc.
- **Network Discovery**: Automatic IP range detection
- **Safe Scanning**: Built-in rate limiting and timeout controls

## 📊 API Reference

### Orchestrator Endpoints

#### System Status
```
GET /status
```
Returns overall system statistics and health.

#### Agent Management
```
GET /agents          # List all agents
POST /agents/register   # Agent registration
POST /agents/heartbeat  # Agent heartbeat
```

#### Job Management
```
POST /jobs/create    # Create new scan job
GET /jobs           # List all jobs
GET /jobs/{job_id}  # Get job details
DELETE /jobs/{job_id} # Delete job
```

#### Task Management
```
POST /tasks/request  # Agent requests task
POST /tasks/results  # Submit task results
```

#### Reporting
```
GET /vulnerabilities # Get prioritized vulnerabilities
```

## 🔒 Security Considerations

### Agent Authentication
- Agents register with unique IDs
- Heartbeat validation prevents spoofing
- Secure communication channels recommended for production

### Safe Scanning
- Built-in rate limiting prevents network disruption
- Timeout controls prevent hanging scans
- Exploit validation uses safe proof-of-concept methods

### Data Protection
- Results encrypted in transit (recommended)
- Centralized logging for audit trails
- Access controls for dashboard

## 🚀 Advanced Features

### Network-Aware Task Distribution
Agents are assigned tasks based on network proximity, reducing scan time and network traffic.

### Adaptive Load Balancing
System monitors agent performance and redistributes tasks for optimal efficiency.

### Exploit Validation Intelligence
Advanced validation engine distinguishes between theoretical and actual vulnerabilities.

### Real-Time Dashboard
Web-based monitoring with live updates and interactive job management.

## 📈 Performance Metrics

### Scalability
- **Linear Scaling**: Performance increases with agent count
- **Network Segmentation**: Agents can scan isolated network segments
- **Resource Optimization**: Intelligent task distribution prevents bottlenecks

### Efficiency
- **Parallel Processing**: Multiple targets scanned simultaneously
- **Smart Scheduling**: Tasks assigned to best-suited agents
- **Result Caching**: Avoids duplicate scanning

### Accuracy
- **Validation Engine**: Eliminates false positives
- **Comprehensive Detection**: Multiple tools and techniques
- **Risk Prioritization**: Focus on critical vulnerabilities

## 🐛 Troubleshooting

### Common Issues

1. **Agents not connecting**
   - Check network connectivity
   - Verify orchestrator URL
   - Check firewall settings

2. **Slow scanning**
   - Increase agent count
   - Check network bandwidth
   - Adjust timeout settings

3. **False positives**
   - Enable exploit validation
   - Update vulnerability databases
   - Review scan configurations

### Logs
- Orchestrator: `orchestrator.log`
- Agents: `agent.log` (on each agent system)
- Dashboard: Browser developer console

## 🤝 Contributing

This system is designed for extensibility:

1. **Add New Scan Types**: Extend agent capabilities
2. **Custom Validation**: Implement domain-specific checks
3. **Integration**: Connect with existing security tools
4. **Reporting**: Add custom report formats

## 📄 License

This distributed VAPT system is provided for educational and authorized security testing purposes only.

## ⚠️ Legal Notice

Use only on systems you own or have explicit permission to test. Unauthorized scanning may violate laws and terms of service.

---

**Revolutionary Distributed Security Assessment - Because security shouldn't be bottlenecked by single points of failure.**