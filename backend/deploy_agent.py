#!/usr/bin/env python3
"""
Agent Deployment Script
=======================

This script helps deploy scanning agents to remote machines
and manage the distributed scanning infrastructure.
"""

import asyncio
import subprocess
import sys
import os
import shutil
from typing import List, Dict, Optional
import argparse
import json

class AgentDeployer:
    def __init__(self, orchestrator_url: str = "http://localhost:8000"):
        self.orchestrator_url = orchestrator_url

    def create_agent_package(self, output_dir: str = "agent_package") -> str:
        """Create a deployable package for agents"""
        print(f"Creating agent package in {output_dir}")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Copy agent files
        agent_files = [
            "agents/scanning_agent.py",
            "requirements-distributed.txt"
        ]

        for file_path in agent_files:
            full_path = os.path.join(os.path.dirname(__file__), file_path)
            if os.path.exists(full_path):
                shutil.copy2(full_path, output_dir)
                print(f"Copied {file_path}")

        # Create deployment script
        deploy_script = f"""#!/bin/bash
# Agent Deployment Script

echo "Deploying Distributed Scanning Agent..."

# Install Python dependencies
pip install -r requirements-distributed.txt

# Install system dependencies (optional, for better scanning capabilities)
# sudo apt-get update
# sudo apt-get install -y nmap rustscan nuclei nikto whatweb httpx sqlmap

# Create agent service
cat > agent.service << EOF
[Unit]
Description=Distributed Scanning Agent
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory={os.getcwd()}/{output_dir}
ExecStart=/usr/bin/python3 scanning_agent.py --orchestrator {self.orchestrator_url}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Install and start service
sudo cp agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable agent
sudo systemctl start agent

echo "Agent deployed and started!"
echo "Check status with: sudo systemctl status agent"
"""

        with open(os.path.join(output_dir, "deploy.sh"), "w") as f:
            f.write(deploy_script)

        # Make deploy script executable
        os.chmod(os.path.join(output_dir, "deploy.sh"), 0o755)

        # Create config file
        config = {
            "orchestrator_url": self.orchestrator_url,
            "agent_id": None,  # Will be auto-generated
            "log_level": "INFO"
        }

        with open(os.path.join(output_dir, "agent_config.json"), "w") as f:
            json.dump(config, f, indent=2)

        # Create README
        readme = f"""# Distributed Scanning Agent

This package contains a distributed vulnerability scanning agent.

## Quick Start

1. Run the deployment script:
   ```bash
   ./deploy.sh
   ```

2. Or run manually:
   ```bash
   pip install -r requirements-distributed.txt
   python3 scanning_agent.py --orchestrator {self.orchestrator_url}
   ```

## Configuration

Edit `agent_config.json` to customize settings.

## Monitoring

The agent will automatically register with the orchestrator at {self.orchestrator_url}
and begin accepting tasks.
"""

        with open(os.path.join(output_dir, "README.md"), "w") as f:
            f.write(readme)

        print(f"Agent package created in {output_dir}")
        return output_dir

    def deploy_to_remote(self, host: str, user: str, key_file: Optional[str] = None,
                        password: Optional[str] = None, package_dir: str = "agent_package"):
        """Deploy agent to remote host via SSH"""
        print(f"Deploying to {host}...")

        try:
            # Create package if it doesn't exist
            if not os.path.exists(package_dir):
                self.create_agent_package(package_dir)

            # Use scp/rsync to copy files
            if key_file:
                scp_cmd = f"scp -i {key_file} -r {package_dir} {user}@{host}:~/"
            else:
                scp_cmd = f"sshpass -p '{password}' scp -r {package_dir} {user}@{host}:~/"

            subprocess.run(scp_cmd, shell=True, check=True)

            # Run deployment script remotely
            if key_file:
                ssh_cmd = f"ssh -i {key_file} {user}@{host} 'cd {package_dir} && ./deploy.sh'"
            else:
                ssh_cmd = f"sshpass -p '{password}' ssh {user}@{host} 'cd {package_dir} && ./deploy.sh'"

            subprocess.run(ssh_cmd, shell=True, check=True)

            print(f"Successfully deployed agent to {host}")

        except subprocess.CalledProcessError as e:
            print(f"Deployment failed: {e}")
            return False

        return True

    def bulk_deploy(self, targets: List[Dict], package_dir: str = "agent_package"):
        """Deploy agents to multiple targets"""
        results = []

        for target in targets:
            host = target['host']
            user = target.get('user', 'root')
            key_file = target.get('key_file')
            password = target.get('password')

            success = self.deploy_to_remote(host, user, key_file, password, package_dir)
            results.append({
                'host': host,
                'success': success
            })

        return results

def main():
    parser = argparse.ArgumentParser(description='Agent Deployment Tool')
    parser.add_argument('--orchestrator', default='http://localhost:8000',
                       help='Orchestrator server URL')
    parser.add_argument('--create-package', action='store_true',
                       help='Create agent package only')
    parser.add_argument('--package-dir', default='agent_package',
                       help='Package directory name')
    parser.add_argument('--deploy-to', help='Deploy to single host (user@host)')
    parser.add_argument('--key-file', help='SSH key file for authentication')
    parser.add_argument('--password', help='SSH password for authentication')
    parser.add_argument('--bulk-deploy', help='JSON file with bulk deployment targets')

    args = parser.parse_args()

    deployer = AgentDeployer(args.orchestrator)

    if args.create_package:
        deployer.create_agent_package(args.package_dir)
    elif args.deploy_to:
        if '@' not in args.deploy_to:
            print("Use format: user@host")
            sys.exit(1)

        user, host = args.deploy_to.split('@', 1)
        deployer.deploy_to_remote(host, user, args.key_file, args.password, args.package_dir)
    elif args.bulk_deploy:
        with open(args.bulk_deploy, 'r') as f:
            targets = json.load(f)

        results = deployer.bulk_deploy(targets, args.package_dir)

        print("\nDeployment Results:")
        for result in results:
            status = "SUCCESS" if result['success'] else "FAILED"
            print(f"{result['host']}: {status}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()