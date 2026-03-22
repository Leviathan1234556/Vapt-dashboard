#!/usr/bin/env python3
"""
Distributed VAPT System Launcher
================================

This script provides an easy way to start the distributed
vulnerability scanning system components.
"""

import subprocess
import sys
import os
import webbrowser
import time
import argparse

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import aiohttp
        print("✓ All Python dependencies found")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Run: pip install -r requirements-distributed.txt")
        return False

def start_orchestrator(port=8000, host="0.0.0.0"):
    """Start the central orchestrator"""
    print(f"🚀 Starting orchestrator on {host}:{port}")

    orchestrator_path = os.path.join(os.path.dirname(__file__), "orchestrator", "orchestrator.py")

    if not os.path.exists(orchestrator_path):
        print(f"✗ Orchestrator not found at {orchestrator_path}")
        return None

    try:
        cmd = [sys.executable, orchestrator_path]
        process = subprocess.Popen(cmd, cwd=os.path.dirname(orchestrator_path))
        print("✓ Orchestrator started")
        return process
    except Exception as e:
        print(f"✗ Failed to start orchestrator: {e}")
        return None

def start_agent(orchestrator_url="http://localhost:8000", agent_id=None):
    """Start a local scanning agent"""
    print(f"🤖 Starting local agent connecting to {orchestrator_url}")

    agent_path = os.path.join(os.path.dirname(__file__), "agents", "scanning_agent.py")

    if not os.path.exists(agent_path):
        print(f"✗ Agent not found at {agent_path}")
        return None

    try:
        cmd = [sys.executable, agent_path, "--orchestrator", orchestrator_url]
        if agent_id:
            cmd.extend(["--agent-id", agent_id])

        process = subprocess.Popen(cmd, cwd=os.path.dirname(agent_path))
        print("✓ Local agent started")
        return process
    except Exception as e:
        print(f"✗ Failed to start agent: {e}")
        return None

def open_dashboard(port=8000):
    """Open the monitoring dashboard"""
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")

    if os.path.exists(dashboard_path):
        dashboard_url = f"file://{os.path.abspath(dashboard_path)}"
        print(f"📊 Opening dashboard: {dashboard_url}")
        webbrowser.open(dashboard_url)
        return True
    else:
        print("✗ Dashboard file not found")
        return False

def main():
    parser = argparse.ArgumentParser(description='Distributed VAPT System Launcher')
    parser.add_argument('--orchestrator-only', action='store_true',
                       help='Start only the orchestrator')
    parser.add_argument('--agent-only', action='store_true',
                       help='Start only a local agent')
    parser.add_argument('--no-dashboard', action='store_true',
                       help='Do not open the dashboard')
    parser.add_argument('--orchestrator-url', default='http://localhost:8000',
                       help='Orchestrator URL for agents')
    parser.add_argument('--port', type=int, default=8000,
                       help='Port for orchestrator')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host for orchestrator')

    args = parser.parse_args()

    print("🔥 Distributed VAPT System Launcher")
    print("=" * 50)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    processes = []

    try:
        # Start orchestrator (unless agent-only mode)
        if not args.agent_only:
            orchestrator_proc = start_orchestrator(args.port, args.host)
            if orchestrator_proc:
                processes.append(("orchestrator", orchestrator_proc))
                # Give orchestrator time to start
                time.sleep(2)
            else:
                print("Failed to start orchestrator")
                sys.exit(1)

        # Start local agent (unless orchestrator-only mode)
        if not args.orchestrator_only:
            agent_proc = start_agent(args.orchestrator_url)
            if agent_proc:
                processes.append(("agent", agent_proc))

        # Open dashboard
        if not args.no_dashboard and not args.agent_only:
            time.sleep(1)  # Give services time to start
            open_dashboard(args.port)

        print("\n" + "=" * 50)
        print("🎉 System started successfully!")
        print(f"📊 Dashboard: Open dashboard.html in your browser")
        print(f"🚀 Orchestrator API: http://localhost:{args.port}")
        print("📖 Documentation: README-DISTRIBUTED.md")
        print("\nPress Ctrl+C to stop all services")
        print("=" * 50)

        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
                # Check if processes are still running
                for name, proc in processes:
                    if proc.poll() is not None:
                        print(f"⚠️  {name} process exited with code {proc.returncode}")

        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")

    finally:
        # Clean up processes
        for name, proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
                print(f"✓ {name} stopped")
            except subprocess.TimeoutExpired:
                proc.kill()
                print(f"⚠️ {name} force killed")

        print("👋 All services stopped")

if __name__ == "__main__":
    main()