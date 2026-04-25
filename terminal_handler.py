import platform
import subprocess
import sys

# Check platform and import appropriate modules
PLATFORM = platform.system()

if PLATFORM == "Darwin":  # macOS
    import pty
    import os
    import select
elif PLATFORM == "Windows":
    # Windows uses subprocess only
    pass
else:  # Linux
    import pty
    import os
    import select

class TerminalHandler:
    """Cross-platform terminal handler"""
    
    def __init__(self):
        self.platform = PLATFORM
        print(f"[PLATFORM] Detected: {self.platform}")
    
    def run_command_windows(self, command):
        """Windows implementation using subprocess"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                print(result.stdout, end='')
            if result.stderr:
                print(result.stderr, file=sys.stderr, end='')
                
            return result.stdout, result.stderr
        except Exception as e:
            print(f"Error running command: {e}")
            return None, str(e)
    
    def run_command_unix(self, command):
        """macOS/Linux implementation using pty"""
        try:
            # Create a pseudo-terminal
            master, slave = pty.openpty()
            
            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                close_fds=True
            )
            
            os.close(slave)
            
            output = []
            while True:
                try:
                    # Read from master with timeout
                    if select.select([master], [], [], 0.1)[0]:
                        data = os.read(master, 1024)
                        if not data:
                            break
                        decoded = data.decode('utf-8', errors='ignore')
                        print(decoded, end='')
                        output.append(decoded)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        # Read any remaining data
                        try:
                            remaining = os.read(master, 1024)
                            if remaining:
                                decoded = remaining.decode('utf-8', errors='ignore')
                                print(decoded, end='')
                                output.append(decoded)
                        except:
                            pass
                        break
                        
                except OSError:
                    break
            
            os.close(master)
            process.wait()
            
            return ''.join(output), None
            
        except Exception as e:
            print(f"Error running command: {e}")
            return None, str(e)
    
    def run_command(self, command):
        """Run command on appropriate platform"""
        if self.platform == "Windows":
            return self.run_command_windows(command)
        else:  # macOS or Linux
            return self.run_command_unix(command)
    
    def get_shell(self):
        """Get default shell for platform"""
        if self.platform == "Windows":
            return "cmd.exe"
        else:
            return os.environ.get('SHELL', '/bin/bash')
