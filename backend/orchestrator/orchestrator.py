#!/usr/bin/env python3
"""
Central Orchestration Engine for Distributed Vulnerability Scanning
==================================================================

This is the main controller that manages distributed scanning agents,
assigns tasks, balances workload, and provides centralized reporting.

Features:
- Agent registration and management
- Intelligent task distribution
- Workload balancing
- Real-time monitoring
- Centralized result aggregation
- Adaptive orchestration based on network conditions
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import heapq

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('orchestrator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AgentInfo(BaseModel):
    agent_id: str
    hostname: str
    ip_addresses: List[str]
    networks: List[str]
    capabilities: Dict[str, bool]
    status: str = "available"
    registered_at: str
    last_heartbeat: Optional[str] = None
    current_task: Optional[str] = None
    system_load: float = 0.0
    memory_usage: float = 0.0

class Task(BaseModel):
    task_id: str
    type: str  # 'port_scan', 'vulnerability_scan', 'exploit_validation', 'service_detection'
    targets: List[str]
    priority: int = 1  # 1=low, 5=high
    assigned_agent: Optional[str] = None
    status: str = "pending"  # pending, assigned, running, completed, failed
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    vulnerabilities: Optional[List[Dict]] = None  # For exploit validation tasks

class ScanJob(BaseModel):
    job_id: str
    name: str
    targets: List[str]
    scan_types: List[str]  # Types of scans to perform
    status: str = "pending"
    created_at: str
    progress: float = 0.0
    tasks: List[str] = []  # Task IDs
    results: Dict = {}

class Orchestrator:
    def __init__(self):
        self.agents: Dict[str, AgentInfo] = {}
        self.tasks: Dict[str, Task] = {}
        self.jobs: Dict[str, ScanJob] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.completed_results: Dict[str, Dict] = {}
        self.agent_networks: Dict[str, Set[str]] = defaultdict(set)
        self.task_assignments: Dict[str, str] = {}  # task_id -> agent_id

        # Task scheduling
        self.task_scheduler_task: Optional[asyncio.Task] = None
        self.agent_monitor_task: Optional[asyncio.Task] = None

        # Statistics
        self.stats = {
            'total_agents': 0,
            'active_agents': 0,
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'uptime': time.time()
        }

    async def start(self):
        """Start the orchestrator background tasks"""
        self.task_scheduler_task = asyncio.create_task(self.task_scheduler())
        self.agent_monitor_task = asyncio.create_task(self.agent_monitor())
        logger.info("Orchestrator background tasks started")

    async def stop(self):
        """Stop the orchestrator background tasks"""
        if self.task_scheduler_task:
            self.task_scheduler_task.cancel()
        if self.agent_monitor_task:
            self.agent_monitor_task.cancel()

        try:
            await self.task_scheduler_task
        except asyncio.CancelledError:
            pass

        try:
            await self.agent_monitor_task
        except asyncio.CancelledError:
            pass

        logger.info("Orchestrator background tasks stopped")

    def register_agent(self, agent_info: Dict) -> Dict:
        """Register a new agent"""
        agent_id = agent_info['agent_id']

        if agent_id in self.agents:
            # Update existing agent
            self.agents[agent_id].last_heartbeat = datetime.now().isoformat()
            self.agents[agent_id].status = "available"
            logger.info(f"Agent {agent_id} re-registered")
        else:
            # New agent
            agent = AgentInfo(**agent_info)
            self.agents[agent_id] = agent

            # Update network mappings
            for network in agent_info.get('networks', []):
                self.agent_networks[network].add(agent_id)

            self.stats['total_agents'] = len(self.agents)
            logger.info(f"New agent registered: {agent_id} ({agent.hostname})")

        return {"status": "registered", "agent_id": agent_id}

    def update_agent_heartbeat(self, heartbeat: Dict):
        """Update agent heartbeat"""
        agent_id = heartbeat['agent_id']

        if agent_id in self.agents:
            self.agents[agent_id].last_heartbeat = heartbeat['timestamp']
            self.agents[agent_id].status = "available" if not heartbeat.get('current_task') else "busy"
            self.agents[agent_id].current_task = heartbeat.get('current_task')
            self.agents[agent_id].system_load = heartbeat.get('system_load', 0.0)
            self.agents[agent_id].memory_usage = heartbeat.get('memory_usage', 0.0)

    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            # Clean up network mappings
            agent = self.agents[agent_id]
            for network in agent.networks:
                self.agent_networks[network].discard(agent_id)

            # Reassign any tasks from this agent
            for task_id, assigned_agent in list(self.task_assignments.items()):
                if assigned_agent == agent_id:
                    self.tasks[task_id].assigned_agent = None
                    self.tasks[task_id].status = "pending"
                    del self.task_assignments[task_id]

            del self.agents[agent_id]
            self.stats['total_agents'] = len(self.agents)
            logger.info(f"Agent unregistered: {agent_id}")

    def create_job(self, name: str, targets: List[str], scan_types: List[str]) -> str:
        """Create a new scan job"""
        job_id = str(uuid.uuid4())
        job = ScanJob(
            job_id=job_id,
            name=name,
            targets=targets,
            scan_types=scan_types,
            created_at=datetime.now().isoformat()
        )

        self.jobs[job_id] = job

        # Create tasks for this job
        tasks = self._create_tasks_for_job(job)
        job.tasks = [task.task_id for task in tasks]

        for task in tasks:
            self.tasks[task.task_id] = task
            asyncio.create_task(self.task_queue.put(task))

        logger.info(f"Created job {job_id} with {len(tasks)} tasks")
        return job_id

    def _create_tasks_for_job(self, job: ScanJob) -> List[Task]:
        """Create individual tasks for a job"""
        tasks = []

        # Group targets by network proximity for better agent assignment
        target_groups = self._group_targets_by_network(job.targets)

        for scan_type in job.scan_types:
            if scan_type == 'port_scan':
                # Create port scan tasks
                for group_targets in target_groups:
                    task = Task(
                        task_id=str(uuid.uuid4()),
                        type='port_scan',
                        targets=group_targets,
                        priority=job.scan_types.index(scan_type) + 1,
                        created_at=datetime.now().isoformat()
                    )
                    tasks.append(task)

            elif scan_type == 'service_detection':
                # Service detection tasks
                for group_targets in target_groups:
                    task = Task(
                        task_id=str(uuid.uuid4()),
                        type='service_detection',
                        targets=group_targets,
                        priority=job.scan_types.index(scan_type) + 1,
                        created_at=datetime.now().isoformat()
                    )
                    tasks.append(task)

            elif scan_type == 'vulnerability_scan':
                # Vulnerability scanning tasks
                for group_targets in target_groups:
                    task = Task(
                        task_id=str(uuid.uuid4()),
                        type='vulnerability_scan',
                        targets=group_targets,
                        priority=job.scan_types.index(scan_type) + 1,
                        created_at=datetime.now().isoformat()
                    )
                    tasks.append(task)

        return tasks

    def _group_targets_by_network(self, targets: List[str]) -> List[List[str]]:
        """Group targets by network proximity"""
        # Simple grouping: assume /24 networks
        network_groups = defaultdict(list)

        for target in targets:
            try:
                # Extract network from IP
                parts = target.split('.')
                if len(parts) == 4:
                    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    network_groups[network].append(target)
                else:
                    # For hostnames, put in a separate group
                    network_groups['hostnames'].append(target)
            except:
                network_groups['unknown'].append(target)

        # Return groups with targets
        return [group for group in network_groups.values() if group]

    def _select_best_agent_for_task(self, task: Task) -> Optional[str]:
        """Select the best agent for a task based on various factors"""
        available_agents = [
            agent_id for agent_id, agent in self.agents.items()
            if agent.status == "available" and self._agent_can_handle_task(agent, task)
        ]

        if not available_agents:
            return None

        # Score agents based on multiple factors
        agent_scores = []

        for agent_id in available_agents:
            agent = self.agents[agent_id]
            score = 0

            # Network proximity (higher score for agents in same network)
            task_networks = set()
            for target in task.targets:
                try:
                    parts = target.split('.')
                    if len(parts) == 4:
                        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        task_networks.add(network)
                except:
                    pass

            agent_network_match = len(task_networks.intersection(self.agent_networks.keys()))
            score += agent_network_match * 10

            # System load (lower load = higher score)
            score += (100 - agent.system_load)

            # Memory usage (lower usage = higher score)
            score += (100 - agent.memory_usage)

            # Capability match
            if self._agent_can_handle_task(agent, task):
                score += 20

            # Random factor to distribute load
            import random
            score += random.randint(0, 10)

            agent_scores.append((score, agent_id))

        # Return agent with highest score
        if agent_scores:
            agent_scores.sort(reverse=True)
            return agent_scores[0][1]

        return None

    def _agent_can_handle_task(self, agent: AgentInfo, task: Task) -> bool:
        """Check if an agent can handle a specific task"""
        required_capabilities = {
            'port_scan': ['port_scanning'],
            'vulnerability_scan': ['vulnerability_scanning'],
            'exploit_validation': ['exploit_validation'],
            'service_detection': ['service_detection']
        }

        required = required_capabilities.get(task.type, [])
        return all(agent.capabilities.get(cap, False) for cap in required)

    async def task_scheduler(self):
        """Background task that assigns tasks to agents"""
        while True:
            try:
                # Get next task from queue
                task = await self.task_queue.get()

                # Find best agent for this task
                best_agent = self._select_best_agent_for_task(task)

                if best_agent:
                    # Assign task to agent
                    task.assigned_agent = best_agent
                    task.status = "assigned"
                    self.task_assignments[task.task_id] = best_agent

                    logger.info(f"Assigned task {task.task_id} to agent {best_agent}")
                else:
                    # No agent available, put back in queue
                    await asyncio.sleep(1)
                    await self.task_queue.put(task)

            except Exception as e:
                logger.error(f"Task scheduler error: {e}")
                await asyncio.sleep(5)

    async def agent_monitor(self):
        """Monitor agent health and handle timeouts"""
        while True:
            try:
                current_time = datetime.now()

                # Check for stale agents
                stale_agents = []
                for agent_id, agent in self.agents.items():
                    if agent.last_heartbeat:
                        last_heartbeat = datetime.fromisoformat(agent.last_heartbeat)
                        if (current_time - last_heartbeat) > timedelta(minutes=5):
                            stale_agents.append(agent_id)

                # Remove stale agents
                for agent_id in stale_agents:
                    logger.warning(f"Removing stale agent: {agent_id}")
                    self.unregister_agent(agent_id)

                # Check for timed out tasks
                for task_id, task in self.tasks.items():
                    if task.status == "running" and task.started_at:
                        started = datetime.fromisoformat(task.started_at)
                        if (current_time - started) > timedelta(minutes=30):
                            logger.warning(f"Task {task_id} timed out")
                            task.status = "failed"
                            self.stats['failed_tasks'] += 1

                            # Reassign if possible
                            if task.assigned_agent:
                                del self.task_assignments[task_id]
                                task.assigned_agent = None
                                task.status = "pending"
                                asyncio.create_task(self.task_queue.put(task))

                # Update statistics
                self.stats['active_agents'] = len([a for a in self.agents.values() if a.status == "available"])

            except Exception as e:
                logger.error(f"Agent monitor error: {e}")

            await asyncio.sleep(60)  # Check every minute

    def submit_task_results(self, results: Dict) -> bool:
        """Handle task results submission from agents"""
        task_id = results['task_id']
        agent_id = results['agent_id']

        if task_id not in self.tasks:
            logger.error(f"Results for unknown task: {task_id}")
            return False

        task = self.tasks[task_id]

        # Update task status
        task.status = results['status']
        task.completed_at = results.get('end_time')

        if task.status == "completed":
            self.stats['completed_tasks'] += 1
        else:
            self.stats['failed_tasks'] += 1

        # Store results
        self.completed_results[task_id] = results

        # Update job progress if this task belongs to a job
        for job in self.jobs.values():
            if task_id in job.tasks:
                completed_tasks = sum(1 for t_id in job.tasks
                                    if self.tasks[t_id].status in ["completed", "failed"])
                job.progress = (completed_tasks / len(job.tasks)) * 100

                # Aggregate results
                if task.status == "completed":
                    job.results[task.type] = job.results.get(task.type, [])
                    job.results[task.type].extend(results.get('results', []))

                # Check if job is complete
                if all(self.tasks[t_id].status in ["completed", "failed"] for t_id in job.tasks):
                    job.status = "completed"
                    logger.info(f"Job {job.job_id} completed")

                break

        # Free up the agent
        if task.assigned_agent:
            del self.task_assignments[task_id]

        logger.info(f"Task {task_id} completed by agent {agent_id}")
        return True

    def get_task_for_agent(self, agent_id: str, capabilities: Dict, network_info: Dict) -> Optional[Dict]:
        """Get a task for a requesting agent"""
        # Find assigned tasks for this agent
        for task_id, assigned_agent in self.task_assignments.items():
            if assigned_agent == agent_id and self.tasks[task_id].status == "assigned":
                task = self.tasks[task_id]
                task.status = "running"
                task.started_at = datetime.now().isoformat()
                self.stats['total_tasks'] += 1

                return task.dict()

        return None

    def get_system_status(self) -> Dict:
        """Get overall system status"""
        return {
            'agents': {
                'total': self.stats['total_agents'],
                'active': self.stats['active_agents'],
                'details': [agent.dict() for agent in self.agents.values()]
            },
            'tasks': {
                'total': len(self.tasks),
                'pending': len([t for t in self.tasks.values() if t.status == "pending"]),
                'running': len([t for t in self.tasks.values() if t.status == "running"]),
                'completed': len([t for t in self.tasks.values() if t.status == "completed"]),
                'failed': len([t for t in self.tasks.values() if t.status == "failed"])
            },
            'jobs': {
                'total': len(self.jobs),
                'active': len([j for j in self.jobs.values() if j.status == "running"]),
                'completed': len([j for j in self.jobs.values() if j.status == "completed"])
            },
            'uptime': time.time() - self.stats['uptime']
        }

    def get_prioritized_vulnerabilities(self, job_id: Optional[str] = None) -> List[Dict]:
        """Get prioritized list of vulnerabilities from completed scans"""
        all_vulnerabilities = []

        # Collect vulnerabilities from results
        for result in self.completed_results.values():
            if result.get('status') == 'completed':
                for scan_result in result.get('results', []):
                    if 'vulnerabilities' in scan_result:
                        for vuln in scan_result['vulnerabilities']:
                            vuln['target'] = scan_result['target']
                            all_vulnerabilities.append(vuln)

        # Prioritize vulnerabilities
        prioritized = []
        severity_weights = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}

        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            weight = severity_weights.get(severity, 0)

            # Add exploitability factor
            if vuln.get('exploitable'):
                weight += 2

            vuln['priority_score'] = weight
            prioritized.append(vuln)

        # Sort by priority score
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)

        return prioritized[:50]  # Top 50 vulnerabilities

# Global orchestrator instance
orchestrator = Orchestrator()

# FastAPI app
app = FastAPI(
    title="Distributed VAPT Orchestrator",
    version="2.0.0",
    description="Central orchestration engine for distributed vulnerability scanning"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await orchestrator.start()

@app.on_event("shutdown")
async def shutdown_event():
    await orchestrator.stop()

@app.post("/agents/register")
async def register_agent(agent_info: Dict):
    """Register a new scanning agent"""
    try:
        result = orchestrator.register_agent(agent_info)
        return result
    except Exception as e:
        logger.error(f"Agent registration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/agents/heartbeat")
async def agent_heartbeat(heartbeat: Dict):
    """Receive heartbeat from agent"""
    try:
        orchestrator.update_agent_heartbeat(heartbeat)
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/agents/unregister")
async def unregister_agent(data: Dict):
    """Unregister an agent"""
    try:
        agent_id = data.get('agent_id')
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id required")

        orchestrator.unregister_agent(agent_id)
        return {"status": "unregistered"}
    except Exception as e:
        logger.error(f"Agent unregistration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tasks/request")
async def request_task(request: Dict):
    """Agent requesting a task"""
    try:
        agent_id = request.get('agent_id')
        capabilities = request.get('capabilities', {})
        network_info = request.get('network_info', {})

        task = orchestrator.get_task_for_agent(agent_id, capabilities, network_info)
        return task or {}
    except Exception as e:
        logger.error(f"Task request error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tasks/results")
async def submit_results(results: Dict):
    """Submit task results from agent"""
    try:
        success = orchestrator.submit_task_results(results)
        return {"status": "received" if success else "error"}
    except Exception as e:
        logger.error(f"Result submission error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/jobs/create")
async def create_job(name: str, targets: List[str], scan_types: List[str]):
    """Create a new scan job"""
    try:
        job_id = orchestrator.create_job(name, targets, scan_types)
        return {"job_id": job_id, "status": "created"}
    except Exception as e:
        logger.error(f"Job creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get job status and results"""
    try:
        if job_id not in orchestrator.jobs:
            raise HTTPException(status_code=404, detail="Job not found")

        job = orchestrator.jobs[job_id]
        return job.dict()
    except Exception as e:
        logger.error(f"Job status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/jobs")
async def list_jobs():
    """List all jobs"""
    try:
        jobs = []
        for job in orchestrator.jobs.values():
            jobs.append({
                'job_id': job.job_id,
                'name': job.name,
                'status': job.status,
                'progress': job.progress,
                'created_at': job.created_at,
                'targets_count': len(job.targets),
                'tasks_count': len(job.tasks)
            })
        return {"jobs": jobs}
    except Exception as e:
        logger.error(f"Jobs list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
async def get_system_status():
    """Get overall system status"""
    try:
        return orchestrator.get_system_status()
    except Exception as e:
        logger.error(f"Status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vulnerabilities")
async def get_vulnerabilities(job_id: Optional[str] = None, limit: int = 100):
    """Get prioritized vulnerabilities"""
    try:
        vulnerabilities = orchestrator.get_prioritized_vulnerabilities(job_id)
        return {"vulnerabilities": vulnerabilities[:limit]}
    except Exception as e:
        logger.error(f"Vulnerabilities error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents")
async def list_agents():
    """List all registered agents"""
    try:
        agents = []
        for agent in orchestrator.agents.values():
            agents.append({
                'agent_id': agent.agent_id,
                'hostname': agent.hostname,
                'ip_addresses': agent.ip_addresses,
                'status': agent.status,
                'capabilities': agent.capabilities,
                'system_load': agent.system_load,
                'memory_usage': agent.memory_usage,
                'last_heartbeat': agent.last_heartbeat
            })
        return {"agents": agents}
    except Exception as e:
        logger.error(f"Agents list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and its tasks"""
    try:
        if job_id not in orchestrator.jobs:
            raise HTTPException(status_code=404, detail="Job not found")

        job = orchestrator.jobs[job_id]

        # Remove tasks
        for task_id in job.tasks:
            if task_id in orchestrator.tasks:
                del orchestrator.tasks[task_id]
            if task_id in orchestrator.completed_results:
                del orchestrator.completed_results[task_id]
            if task_id in orchestrator.task_assignments:
                del orchestrator.task_assignments[task_id]

        # Remove job
        del orchestrator.jobs[job_id]

        return {"status": "deleted"}
    except Exception as e:
        logger.error(f"Job deletion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)