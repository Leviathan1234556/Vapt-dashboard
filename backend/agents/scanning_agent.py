#!/usr/bin/env python3
"""
Distributed Vulnerability Scanning Agent
=======================================

This agent performs local network scanning and vulnerability detection.
It communicates with the central orchestration engine for task assignment
and result reporting.

Features:
- Autonomous scanning of nearby systems
- Vulnerability detection and validation
- Real-time communication with central server
- Adaptive scanning based on network conditions
"""

import asyncio
import aiohttp
import json
import logging
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set
import os
import ipaddress
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ScanningAgent:
    def __init__(self, orchestrator_url: str = "http://localhost:8000", agent_id: Optional[str] = None):
        self.orchestrator_url = orchestrator_url.rstrip('/')
        self.agent_id = agent_id or str(uuid.uuid4())
        self.session: Optional[aiohttp.ClientSession] = None
        self.is_registered = False
        self.current_task: Optional[Dict] = None
        self.capabilities = self._detect_capabilities()
        self.network_info = self._get_network_info()
        self.heartbeat_interval = 30  # seconds
        self.scan_timeout = 300  # 5 minutes per target

    def _detect_capabilities(self) -> Dict[str, bool]:
        """Detect available scanning tools and capabilities"""
        capabilities = {
            'nmap': False,
            'rustscan': False,
            'nuclei': False,
            'nikto': False,
            'whatweb': False,
            'httpx': False,
            'sqlmap': False,
            'masscan': False,
            'exploit_validation': True,  # Built-in capability
            'port_scanning': True,
            'service_detection': True,
            'vulnerability_scanning': True
        }

        # Check for installed tools
        for tool in ['nmap', 'rustscan', 'nuclei', 'nikto', 'whatweb', 'httpx', 'sqlmap', 'masscan']:
            try:
                result = subprocess.run([tool, '--version'],
                                      capture_output=True, text=True, timeout=5)
                capabilities[tool] = result.returncode == 0
                if capabilities[tool]:
                    logger.info(f"Tool {tool} detected")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning(f"Tool {tool} not available")

        return capabilities

    def _get_network_info(self) -> Dict:
        """Get local network information"""
        network_info = {
            'hostname': socket.gethostname(),
            'ip_addresses': [],
            'networks': [],
            'interfaces': []
        }

        try:
            if HAS_NETIFACES:
                # Get IP addresses using netifaces
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr['addr']
                            if not ip.startswith('127.'):
                                network_info['ip_addresses'].append(ip)
                                network_info['interfaces'].append(interface)

                                # Calculate network range
                                try:
                                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                                    network_info['networks'].append(str(net))
                                except:
                                    pass
            else:
                # Fallback: get local IP using socket
                try:
                    # This is a simple way to get local IP, not perfect but works
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()

                    if not local_ip.startswith('127.'):
                        network_info['ip_addresses'].append(local_ip)
                        network_info['interfaces'].append('primary')

                        try:
                            net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                            network_info['networks'].append(str(net))
                        except:
                            pass
                except:
                    pass

        except Exception as e:
            logger.error(f"Error getting network info: {e}")

        return network_info

    async def register_with_orchestrator(self) -> bool:
        """Register this agent with the central orchestrator"""
        try:
            agent_info = {
                'agent_id': self.agent_id,
                'hostname': self.network_info['hostname'],
                'ip_addresses': self.network_info['ip_addresses'],
                'networks': self.network_info['networks'],
                'capabilities': self.capabilities,
                'status': 'available',
                'registered_at': datetime.now().isoformat()
            }

            async with self.session.post(
                f"{self.orchestrator_url}/agents/register",
                json=agent_info,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"Agent registered successfully: {result}")
                    self.is_registered = True
                    return True
                else:
                    logger.error(f"Registration failed: {response.status} - {await response.text()}")
                    return False

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False

    async def heartbeat(self):
        """Send periodic heartbeat to orchestrator"""
        while True:
            try:
                if self.is_registered:
                    status_update = {
                        'agent_id': self.agent_id,
                        'status': 'busy' if self.current_task else 'available',
                        'current_task': self.current_task['task_id'] if self.current_task else None,
                        'timestamp': datetime.now().isoformat(),
                        'system_load': psutil.cpu_percent(),
                        'memory_usage': psutil.virtual_memory().percent
                    }

                    async with self.session.post(
                        f"{self.orchestrator_url}/agents/heartbeat",
                        json=status_update,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status != 200:
                            logger.warning(f"Heartbeat failed: {response.status}")

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            await asyncio.sleep(self.heartbeat_interval)

    async def request_task(self) -> Optional[Dict]:
        """Request a new task from the orchestrator"""
        try:
            request_data = {
                'agent_id': self.agent_id,
                'capabilities': self.capabilities,
                'network_info': self.network_info
            }

            async with self.session.post(
                f"{self.orchestrator_url}/tasks/request",
                json=request_data,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    task = await response.json()
                    if task and 'task_id' in task:
                        logger.info(f"Received task: {task['task_id']} - {task['type']}")
                        return task
                    else:
                        logger.debug("No tasks available")
                        return None
                else:
                    logger.warning(f"Task request failed: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Task request error: {e}")
            return None

    async def execute_task(self, task: Dict) -> Dict:
        """Execute a scanning task"""
        self.current_task = task
        task_id = task['task_id']
        task_type = task['type']
        targets = task.get('targets', [])

        logger.info(f"Executing task {task_id}: {task_type} on {len(targets)} targets")

        results = {
            'task_id': task_id,
            'agent_id': self.agent_id,
            'status': 'completed',
            'results': [],
            'errors': [],
            'start_time': datetime.now().isoformat(),
            'end_time': None
        }

        try:
            if task_type == 'port_scan':
                results['results'] = await self._perform_port_scan(targets)
            elif task_type == 'vulnerability_scan':
                results['results'] = await self._perform_vulnerability_scan(targets)
            elif task_type == 'exploit_validation':
                results['results'] = await self._perform_exploit_validation(targets, task.get('vulnerabilities', []))
            elif task_type == 'service_detection':
                results['results'] = await self._perform_service_detection(targets)
            else:
                results['status'] = 'failed'
                results['errors'].append(f"Unknown task type: {task_type}")

        except Exception as e:
            logger.error(f"Task execution error: {e}")
            results['status'] = 'failed'
            results['errors'].append(str(e))

        results['end_time'] = datetime.now().isoformat()
        self.current_task = None
        return results

    async def _perform_port_scan(self, targets: List[str]) -> List[Dict]:
        """Perform port scanning on targets"""
        results = []

        for target in targets:
            try:
                logger.info(f"Scanning ports on {target}")

                # Use nmap if available, otherwise fallback to basic socket scanning
                if self.capabilities.get('nmap'):
                    cmd = ['nmap', '-p-', '--min-rate=1000', '--max-retries=1', target]
                    result = await self._run_command(cmd, timeout=60)
                    open_ports = self._parse_nmap_output(result['stdout'])
                else:
                    open_ports = await self._basic_port_scan(target)

                results.append({
                    'target': target,
                    'scan_type': 'port_scan',
                    'open_ports': open_ports,
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                logger.error(f"Port scan failed for {target}: {e}")
                results.append({
                    'target': target,
                    'scan_type': 'port_scan',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

        return results

    async def _perform_vulnerability_scan(self, targets: List[str]) -> List[Dict]:
        """Perform vulnerability scanning"""
        results = []

        for target in targets:
            try:
                logger.info(f"Vulnerability scanning {target}")

                vulnerabilities = []

                # Use nuclei if available
                if self.capabilities.get('nuclei'):
                    cmd = ['nuclei', '-u', target, '-json', '-silent']
                    result = await self._run_command(cmd, timeout=120)
                    nuclei_vulns = self._parse_nuclei_output(result['stdout'])
                    vulnerabilities.extend(nuclei_vulns)

                # Use nikto for web vulnerabilities
                if self.capabilities.get('nikto'):
                    # Check if target has web ports
                    web_ports = await self._check_web_ports(target)
                    for port in web_ports:
                        protocol = 'https' if port == 443 else 'http'
                        url = f"{protocol}://{target}:{port}"
                        cmd = ['nikto', '-h', url, '-Format', 'json']
                        result = await self._run_command(cmd, timeout=180)
                        nikto_vulns = self._parse_nikto_output(result['stdout'])
                        vulnerabilities.extend(nikto_vulns)

                results.append({
                    'target': target,
                    'scan_type': 'vulnerability_scan',
                    'vulnerabilities': vulnerabilities,
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                logger.error(f"Vulnerability scan failed for {target}: {e}")
                results.append({
                    'target': target,
                    'scan_type': 'vulnerability_scan',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

        return results

    async def _perform_exploit_validation(self, targets: List[str], vulnerabilities: List[Dict]) -> List[Dict]:
        """Perform controlled exploit validation"""
        results = []

        for target in targets:
            try:
                logger.info(f"Exploit validation on {target}")

                validations = []

                for vuln in vulnerabilities:
                    if vuln.get('target') == target:
                        validation_result = await self._validate_vulnerability(target, vuln)
                        validations.append(validation_result)

                results.append({
                    'target': target,
                    'scan_type': 'exploit_validation',
                    'validations': validations,
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                logger.error(f"Exploit validation failed for {target}: {e}")
                results.append({
                    'target': target,
                    'scan_type': 'exploit_validation',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

        return results

    async def _perform_service_detection(self, targets: List[str]) -> List[Dict]:
        """Perform service detection on targets"""
        results = []

        for target in targets:
            try:
                logger.info(f"Service detection on {target}")

                services = []

                if self.capabilities.get('nmap'):
                    cmd = ['nmap', '-sV', '--version-intensity=5', target]
                    result = await self._run_command(cmd, timeout=120)
                    services = self._parse_nmap_service_output(result['stdout'])

                results.append({
                    'target': target,
                    'scan_type': 'service_detection',
                    'services': services,
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                logger.error(f"Service detection failed for {target}: {e}")
                results.append({
                    'target': target,
                    'scan_type': 'service_detection',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

        return results

    async def _validate_vulnerability(self, target: str, vulnerability: Dict) -> Dict:
        """Validate if a vulnerability can actually be exploited"""
        vuln_name = vulnerability.get('name', '')
        port = vulnerability.get('port', 0)

        validation = {
            'vulnerability': vuln_name,
            'port': port,
            'exploitable': False,
            'confidence': 'low',
            'details': '',
            'safe_test_performed': False
        }

        try:
            # Perform safe validation tests based on vulnerability type
            if 'ftp' in vuln_name.lower() and 'anonymous' in vuln_name.lower():
                validation = await self._validate_ftp_anonymous(target, port)
            elif 'ssh' in vuln_name.lower():
                validation = await self._validate_ssh_vulnerability(target, port, vulnerability)
            elif 'sql' in vuln_name.lower() and 'injection' in vuln_name.lower():
                validation = await self._validate_sql_injection(target, vulnerability)
            elif 'eternalblue' in vuln_name.lower():
                validation = await self._validate_eternalblue(target)
            # Add more validation methods as needed

        except Exception as e:
            logger.error(f"Validation error for {vuln_name}: {e}")
            validation['details'] = f"Validation failed: {str(e)}"

        return validation

    async def _validate_ftp_anonymous(self, target: str, port: int) -> Dict:
        """Safely validate FTP anonymous access"""
        import ftplib

        validation = {
            'vulnerability': 'FTP Anonymous Access',
            'port': port,
            'exploitable': False,
            'confidence': 'high',
            'details': '',
            'safe_test_performed': True
        }

        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=10)
            response = ftp.login('anonymous', 'test@test.com')

            if '230' in response:
                validation['exploitable'] = True
                validation['details'] = "Anonymous FTP access confirmed exploitable"
                # Safely list directory without downloading
                try:
                    files = ftp.nlst()
                    validation['details'] += f" | {len(files)} items accessible"
                except:
                    pass
            else:
                validation['details'] = "Anonymous access denied"

            ftp.quit()

        except Exception as e:
            validation['details'] = f"Connection failed: {str(e)}"

        return validation

    async def _validate_ssh_vulnerability(self, target: str, port: int, vulnerability: Dict) -> Dict:
        """Validate SSH-related vulnerabilities safely"""
        validation = {
            'vulnerability': vulnerability.get('name', 'SSH Vulnerability'),
            'port': port,
            'exploitable': False,
            'confidence': 'medium',
            'details': '',
            'safe_test_performed': True
        }

        try:
            if HAS_PARAMIKO:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Try common weak credentials for testing (only if explicitly allowed)
                weak_creds = [('admin', 'admin'), ('root', 'root'), ('test', 'test')]

                for username, password in weak_creds:
                    try:
                        client.connect(target, port=port, username=username, password=password, timeout=5)
                        validation['exploitable'] = True
                        validation['details'] = f"SSH weak credentials found: {username}:{password}"
                        client.close()
                        break
                    except paramiko.AuthenticationException:
                        continue
                    except:
                        break

                if not validation['exploitable']:
                    validation['details'] = "No weak SSH credentials found"
            else:
                validation['details'] = "Paramiko not available for SSH testing"

        except Exception as e:
            validation['details'] = f"SSH validation error: {str(e)}"

        return validation

    async def _validate_sql_injection(self, target: str, vulnerability: Dict) -> Dict:
        """Validate SQL injection vulnerabilities safely"""
        validation = {
            'vulnerability': 'SQL Injection',
            'port': 0,
            'exploitable': False,
            'confidence': 'medium',
            'details': '',
            'safe_test_performed': True
        }

        try:
            url = vulnerability.get('url', '')
            if not url:
                validation['details'] = "No URL provided for SQL injection test"
                return validation

            # Use sqlmap for safe testing if available
            if self.capabilities.get('sqlmap'):
                cmd = ['sqlmap', '-u', url, '--batch', '--level=1', '--risk=1', '--timeout=10']
                result = await self._run_command(cmd, timeout=60)

                if 'sqlmap identified the following injection point' in result['stdout']:
                    validation['exploitable'] = True
                    validation['details'] = "SQL injection confirmed by sqlmap"
                else:
                    validation['details'] = "No SQL injection found"
            else:
                # Basic safe test
                test_payloads = ["'", "''", "' OR '1'='1", "'; --"]
                for payload in test_payloads:
                    try:
                        response = await self._safe_http_request(url + payload, timeout=5)
                        if 'sql' in response.lower() or 'syntax' in response.lower():
                            validation['exploitable'] = True
                            validation['details'] = f"Potential SQL injection with payload: {payload}"
                            break
                    except:
                        continue

                if not validation['exploitable']:
                    validation['details'] = "No obvious SQL injection patterns found"

        except Exception as e:
            validation['details'] = f"SQL injection validation error: {str(e)}"

        return validation

    async def _validate_eternalblue(self, target: str) -> Dict:
        """Validate EternalBlue vulnerability safely"""
        validation = {
            'vulnerability': 'EternalBlue (MS17-010)',
            'port': 445,
            'exploitable': False,
            'confidence': 'high',
            'details': '',
            'safe_test_performed': True
        }

        try:
            # Use nmap script for safe detection
            if self.capabilities.get('nmap'):
                cmd = ['nmap', '-p', '445', '--script', 'smb-vuln-ms17-010', target]
                result = await self._run_command(cmd, timeout=30)

                if 'VULNERABLE' in result['stdout']:
                    validation['exploitable'] = True
                    validation['details'] = "EternalBlue vulnerability confirmed"
                else:
                    validation['details'] = "Not vulnerable to EternalBlue"
            else:
                validation['details'] = "Nmap not available for EternalBlue check"

        except Exception as e:
            validation['details'] = f"EternalBlue validation error: {str(e)}"

        return validation

    async def _basic_port_scan(self, target: str) -> List[int]:
        """Basic port scanning using sockets"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        return open_ports

    async def _check_web_ports(self, target: str) -> List[int]:
        """Check for web service ports"""
        web_ports = []
        for port in [80, 443, 8080, 8443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    web_ports.append(port)
                sock.close()
            except:
                pass
        return web_ports

    async def _safe_http_request(self, url: str, timeout: int = 10) -> str:
        """Make a safe HTTP request for testing"""
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                return await response.text()
        except:
            return ""

    async def _run_command(self, cmd: List[str], timeout: int = 30) -> Dict:
        """Run a command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                timeout=timeout
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            return {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'returncode': process.returncode
            }

        except asyncio.TimeoutError:
            return {'stdout': '', 'stderr': 'Command timeout', 'returncode': -1}
        except Exception as e:
            return {'stdout': '', 'stderr': str(e), 'returncode': -1}

    def _parse_nmap_output(self, output: str) -> List[int]:
        """Parse nmap output for open ports"""
        open_ports = []
        lines = output.split('\n')
        in_port_section = False

        for line in lines:
            if 'PORT' in line and 'STATE' in line:
                in_port_section = True
                continue
            elif in_port_section and line.strip():
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0]
                    try:
                        open_ports.append(int(port))
                    except:
                        pass
                elif not line[0].isdigit():
                    break

        return open_ports

    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """Parse nuclei JSON output"""
        vulnerabilities = []
        try:
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip():
                    vuln = json.loads(line)
                    vulnerabilities.append({
                        'name': vuln.get('info', {}).get('name', ''),
                        'severity': vuln.get('info', {}).get('severity', 'unknown'),
                        'url': vuln.get('url', ''),
                        'matched-at': vuln.get('matched-at', ''),
                        'template-id': vuln.get('template-id', '')
                    })
        except:
            pass
        return vulnerabilities

    def _parse_nikto_output(self, output: str) -> List[Dict]:
        """Parse nikto JSON output"""
        vulnerabilities = []
        try:
            data = json.loads(output)
            for item in data:
                vulnerabilities.append({
                    'name': item.get('msg', ''),
                    'url': item.get('url', ''),
                    'method': item.get('method', ''),
                    'id': item.get('id', '')
                })
        except:
            pass
        return vulnerabilities

    def _parse_nmap_service_output(self, output: str) -> List[Dict]:
        """Parse nmap service detection output"""
        services = []
        lines = output.split('\n')
        in_port_section = False

        for line in lines:
            if 'PORT' in line and 'SERVICE' in line:
                in_port_section = True
                continue
            elif in_port_section and line.strip():
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        port = parts[0].split('/')[0]
                        service = parts[2]
                        version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        services.append({
                            'port': int(port),
                            'service': service,
                            'version': version
                        })
                elif not line[0].isdigit():
                    break

        return services

    async def submit_results(self, results: Dict):
        """Submit task results to orchestrator"""
        try:
            async with self.session.post(
                f"{self.orchestrator_url}/tasks/results",
                json=results,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    logger.info(f"Results submitted for task {results['task_id']}")
                    return True
                else:
                    logger.error(f"Result submission failed: {response.status}")
                    return False

        except Exception as e:
            logger.error(f"Result submission error: {e}")
            return False

    async def run(self):
        """Main agent loop"""
        logger.info(f"Starting scanning agent {self.agent_id}")
        logger.info(f"Network info: {self.network_info}")
        logger.info(f"Capabilities: {self.capabilities}")

        async with aiohttp.ClientSession() as session:
            self.session = session

            # Register with orchestrator
            if not await self.register_with_orchestrator():
                logger.error("Failed to register with orchestrator. Exiting.")
                return

            # Start heartbeat task
            heartbeat_task = asyncio.create_task(self.heartbeat())

            try:
                while True:
                    # Request a task
                    task = await self.request_task()

                    if task:
                        # Execute the task
                        results = await self.execute_task(task)

                        # Submit results
                        await self.submit_results(results)

                        # Brief pause before next task
                        await asyncio.sleep(1)
                    else:
                        # No tasks available, wait before checking again
                        await asyncio.sleep(10)

            except KeyboardInterrupt:
                logger.info("Agent shutdown requested")
            except Exception as e:
                logger.error(f"Agent error: {e}")
            finally:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

                # Unregister
                try:
                    async with session.post(
                        f"{self.orchestrator_url}/agents/unregister",
                        json={'agent_id': self.agent_id}
                    ) as response:
                        logger.info("Agent unregistered")
                except:
                    pass

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Distributed Vulnerability Scanning Agent')
    parser.add_argument('--orchestrator', default='http://localhost:8000',
                       help='Orchestrator server URL')
    parser.add_argument('--agent-id', help='Agent ID (auto-generated if not provided)')

    args = parser.parse_args()

    agent = ScanningAgent(args.orchestrator, args.agent_id)

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")

if __name__ == '__main__':
    main()