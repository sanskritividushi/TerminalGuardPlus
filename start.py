import asyncio
import subprocess
import sys
import os

async def run_process(cmd_args):
    """Run a subprocess and keep it alive"""
    # Set working directory to script location
    cwd = os.path.dirname(os.path.abspath(__file__))
    proc = await asyncio.create_subprocess_exec(
        *cmd_args,
        cwd=cwd,
        # Remove stdout and stderr redirection to see logs
        stdout=None,  # ← Changed from asyncio.subprocess.PIPE
        stderr=None   # ← Changed from asyncio.subprocess.PIPE
    )
    
    # Don't wait - let processes run concurrently
    return proc

async def main():
    print("Starting TerminalGuard services...")
    
    # Ensure we're in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    python_executable = sys.executable
    
    # Start all three services
    processes = []
    processes.append(await run_process([python_executable, "test_email_server.py"]))
    processes.append(await run_process([python_executable, "dashboard_api.py"]))
    processes.append(await run_process([python_executable, "mcp_middleware.py"]))
    
    print("All services started successfully")
    
    # Keep the main process alive and monitor subprocesses
    try:
        while True:
            await asyncio.sleep(1)
            # Check if any process died
            for proc in processes:
                if proc.returncode is not None:
                    print(f"Process {proc.pid} exited with code {proc.returncode}")
    except KeyboardInterrupt:
        print("Shutting down services...")
        for proc in processes:
            proc.terminate()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutdown complete")
