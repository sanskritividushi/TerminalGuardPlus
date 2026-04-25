import asyncio
import json
import sys
import time
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from secret_detector import SecretDetector
from config_manager import ConfigManager
from audit_logger import AuditLogger
from ml.cascade_entropy_detector import CascadeEnsembleDetector


class TerminalGuardMiddleware:
    """MCP Middleware that intercepts and scans MCP server calls for secrets"""
    
    def __init__(self, target_server_command: str, target_server_args: list[str] = None):
        self.server = Server("terminalguard-middleware")
        self.target_command = target_server_command
        self.target_args = target_server_args or []
        
        try:
            import os
            mongodb_uri = os.getenv('MONGODB_URI')
            if mongodb_uri:
                print(f"[MIDDLEWARE] ✅ MONGODB_URI detected: {mongodb_uri[:30]}...", file=sys.stderr)
            else:
                print("[MIDDLEWARE] ⚠️ WARNING: MONGODB_URI not set in environment!", file=sys.stderr)

            self.config_manager = ConfigManager()

            # L3 regex detector (kept for pattern hits)
            self.regex_detector = SecretDetector(self.config_manager)

            # Main cascade detector (BiLSTM + SVM + Entropy + Regex)
            self.cascade = CascadeEnsembleDetector()

            self.logger = AuditLogger()
            print("[MIDDLEWARE] Components initialized successfully", file=sys.stderr)

            print("[DEBUG] Python version:", sys.version, file=sys.stderr)
            
        except Exception as e:
            print(f"[MIDDLEWARE] Error initializing components: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise
        
        self.target_session: ClientSession = None
        self.target_tools = []
        self.stdio_context = None
        self.read_stream = None
        self.write_stream = None
    
    async def connect_to_target_server(self):
        """Connect to the target MCP server"""
        try:
            print("[MIDDLEWARE] Connecting to target server...", file=sys.stderr)
            
            server_params = StdioServerParameters(
                command=self.target_command,
                args=self.target_args
            )
            
            # Store the context manager for proper cleanup
            self.stdio_context = stdio_client(server_params)
            self.read_stream, self.write_stream = await self.stdio_context.__aenter__()
            
            print("[MIDDLEWARE] stdio_client connected", file=sys.stderr)
            
            self.target_session = ClientSession(self.read_stream, self.write_stream)
            await self.target_session.__aenter__()
            
            print("[MIDDLEWARE] ClientSession created", file=sys.stderr)
            
            # Initialize the target server
            await self.target_session.initialize()
            
            print("[MIDDLEWARE] Target server initialized", file=sys.stderr)
            
            # Get available tools from target server
            tools_response = await self.target_session.list_tools()
            self.target_tools = tools_response.tools
            
            print(f"[MIDDLEWARE] Connected to target server", file=sys.stderr)
            print(f"[MIDDLEWARE] Available tools: {[tool.name for tool in self.target_tools]}", file=sys.stderr)
        
        except Exception as e:
            print(f"[MIDDLEWARE] Error connecting to target server: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise
    
    async def cleanup(self):
        """Properly cleanup connections"""
        try:
            if self.target_session:
                await self.target_session.__aexit__(None, None, None)
                print("[MIDDLEWARE] Closed target session", file=sys.stderr)
            
            if self.stdio_context:
                await self.stdio_context.__aexit__(None, None, None)
                print("[MIDDLEWARE] Closed stdio context", file=sys.stderr)
        
        except Exception as e:
            print(f"[MIDDLEWARE] Error during cleanup: {e}", file=sys.stderr)
    
    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Return tools from target server plus security tools"""
            print("[MIDDLEWARE] list_tools called", file=sys.stderr)
            
            security_tools = [
                Tool(
                    name="security_scan",
                    description="Manually scan text for secrets (TerminalGuard)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to scan for secrets"
                            }
                        },
                        "required": ["text"]
                    }
                ),
                Tool(
                    name="get_security_stats",
                    description="Get security statistics (TerminalGuard)",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]
            
            all_tools = self.target_tools + security_tools
            print(f"[MIDDLEWARE] Returning {len(all_tools)} tools", file=sys.stderr)
            return all_tools
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            """Intercept tool calls and scan for secrets"""
            print("[DEBUG] call_tool received:", name, file=sys.stderr)

            print(f"[MIDDLEWARE] call_tool: {name}", file=sys.stderr)
            
            # Handle our security tools
            if name == "security_scan":
                return await self.manual_scan(arguments.get("text", ""))
            
            if name == "get_security_stats":
                return await self.get_stats()
            
            # For other tools, scan and forward
            return await self.intercept_and_forward(name, arguments)
        
    def filter_false_positives(self, tool_name: str, arguments: dict, secrets: list) -> list:
        """Filter out false positive detections based on tool context"""
        if not secrets:
            return secrets

        filtered_secrets = []

        # For send_email and similar tools, ignore email addresses in recipient fields
        email_tools = ['send_email', 'send_mail', 'email']
        email_params = ['to', 'from', 'cc', 'bcc', 'recipient', 'sender', 'reply_to']

        if tool_name.lower() in email_tools or 'email' in tool_name.lower():
            # Get all email addresses from expected parameter fields
            expected_emails = set()
            for param in email_params:
                if param in arguments:
                    value = arguments[param]
                    # Handle both string and list values
                    if isinstance(value, str):
                        expected_emails.add(value.lower())
                    elif isinstance(value, list):
                        expected_emails.update(v.lower() for v in value if isinstance(v, str))

            print(f"[MIDDLEWARE] Expected emails for {tool_name}: {expected_emails}", file=sys.stderr)

            # Filter out email pattern matches that are in expected fields
            for secret in secrets:
                if secret['type'] == 'email':
                    # Check if this email is in an expected parameter
                    if secret['match'].lower() in expected_emails:
                        print(f"[MIDDLEWARE] Filtering false positive: {secret['match']} (expected email parameter)", file=sys.stderr)
                        continue  # Skip this false positive

                filtered_secrets.append(secret)
        else:
            # For non-email tools, return all secrets
            filtered_secrets = secrets

        return filtered_secrets

    async def intercept_and_forward(self, tool_name: str, arguments: dict) -> list[TextContent]:
        """Intercept tool call, scan for secrets, and forward to target server"""
        start_time = time.perf_counter()
        print("[DEBUG] intercept_and_forward called for tool:", tool_name, file=sys.stderr)

        # # Convert arguments to string for scanning
        # args_str = json.dumps(arguments)

        # print(f"[MIDDLEWARE] Intercepting: {tool_name}", file=sys.stderr)
        # print(f"[MIDDLEWARE] Arguments: {args_str[:200]}", file=sys.stderr)

        # # Scan for secrets
        # detected_secrets = self.detector.detect(args_str)

        # # Filter out false positives based on tool context
        # secrets = self.filter_false_positives(tool_name, arguments, detected_secrets)

        # # Calculate detection latency
        # detection_latency_ms = (time.perf_counter() - start_time) * 1000

        # if detected_secrets and not secrets:
        #     print(f"[MIDDLEWARE] ✅ All {len(detected_secrets)} detection(s) were false positives, filtered out", file=sys.stderr)
        
        # if secrets:
        #     # Secret detected - BLOCK
            
        #     print(f"[MIDDLEWARE] ⚠️ BLOCKED: {len(secrets)} secret(s) detected!", file=sys.stderr)
            
        #     warning = "🚨 SECURITY ALERT - TerminalGuard 🚨\n\n"
        #     warning += f"Detected {len(secrets)} secret(s) in your '{tool_name}' request:\n\n"
            
        #     for i, secret in enumerate(secrets, 1):
        #         warning += f"{i}. {secret['type'].upper()} (Severity: {secret['severity']})\n"
        #         warning += f"   {secret['description']}\n"
        #         warning += f"   Detected: {secret['match'][:30]}...\n\n"
            
        #     warning += "❌ Operation BLOCKED to protect sensitive information.\n"
        #     warning += "Please remove secrets and try again."
            
        #     print("[DEBUG] About to log the blocked attempt...", file=sys.stderr)
        #     try:
        #         self.logger.log_event(
        #             command=f"MCP:{tool_name} - {args_str[:100]}",
        #             secrets_detected=secrets,
        #             action='BLOCKED',
        #             user_choice='automatic',
        #             latency_ms=round(detection_latency_ms, 3)
        #         )
        #         print(f"[DEBUG] Blocked attempt logged successfully. Latency: {detection_latency_ms:.3f}ms", file=sys.stderr)
        #     except Exception as e:
        #         print(f"[ERROR] Failed to log blocked attempt: {e}", file=sys.stderr)
        #         import traceback
        #         traceback.print_exc()
            
        #     return [TextContent(type="text", text=warning)]
        
        # # No secrets - forward to target server
        # print(f"[MIDDLEWARE] ✅ Safe. Forwarding to target...", file=sys.stderr)

        # Convert arguments to string for scanning
        args_str = json.dumps(arguments)

        print(f"[MIDDLEWARE] Intercepting: {tool_name}", file=sys.stderr)
        print(f"[MIDDLEWARE] Arguments: {args_str[:200]}", file=sys.stderr)

        # ... inside intercept_and_forward, after cascade_result = self.cascade.detect(args_str)

        cascade_result = self.cascade.detect(args_str)

        blocked = cascade_result["decision"]
        cascade_level = cascade_result["cascade_level"]
        confidence = cascade_result["confidence"]
        reason = cascade_result["reasoning"]
        probs = cascade_result["probs"]

        detected_secrets = self.regex_detector.detect(args_str)
        secrets = self.filter_false_positives(tool_name, arguments, detected_secrets)

        detection_latency_ms = (time.perf_counter() - start_time) * 1000

        if blocked or secrets:
            print(
                f"[MIDDLEWARE] BLOCKED by cascade L{cascade_level} (conf={confidence:.3f})",
                file=sys.stderr,
            )

            warning = "SECURITY ALERT - TerminalGuard\n\n"
            warning += f"Cascade decision: {'BLOCK' if blocked else 'ALLOW (regex hits)'}\n"
            warning += f"Level: L{cascade_level}, confidence={confidence:.3f}\n"
            warning += f"Reason: {reason}\n\n"

            if secrets:
                warning += f"Detected {len(secrets)} secret(s):\n\n"
                for i, secret in enumerate(secrets, 1):
                    warning += f"{i}. {secret['type'].upper()} (Severity: {secret['severity']})\n"
                    warning += f"   {secret['description']}\n"
                    warning += f"   Detected: {secret['match'][:30]}...\n\n"

            warning += "Operation BLOCKED to protect sensitive information.\n"
            warning += "Please remove secrets and try again."

            try:
                self.logger.log_event(
                    command=f"MCP:{tool_name} - {args_str[:100]}",
                    secrets_detected=secrets,
                    action="BLOCKED",
                    user_choice="automatic",
                    latency_ms=round(detection_latency_ms, 3),
                    extra={
                        "cascade_level": cascade_level,
                        "cascade_confidence": confidence,
                        "cascade_reason": reason,
                        "cascade_probs": probs,
                    },
                )
            except Exception as e:
                print(f"[ERROR] Failed to log blocked attempt: {e}", file=sys.stderr)

            return [TextContent(type="text", text=warning)]

        # Safe path
        print(
            f"[MIDDLEWARE] Safe by cascade (L{cascade_level}, conf={confidence:.3f}). Forwarding to target...",
            file=sys.stderr,
        )

        result = await self.target_session.call_tool(tool_name, arguments)

        self.logger.log_event(
            command=f"MCP:{tool_name} - {args_str[:100]}",
            secrets_detected=[],
            action="ALLOWED",
            user_choice=None,
            latency_ms=round(detection_latency_ms, 3),
            extra={
                "cascade_level": cascade_level,
                "cascade_confidence": confidence,
                "cascade_reason": reason,
                "cascade_probs": probs,
            },
        )

        return result.content

    async def manual_scan(self, text: str) -> list[TextContent]:
        """Manually scan text for secrets"""
        secrets = self.regex_detector.detect(text)
        
        if secrets:
            result = "🔍 TerminalGuard Scan Results:\n\n"
            result += f"⚠️ Found {len(secrets)} secret(s):\n\n"
            for i, secret in enumerate(secrets, 1):
                result += f"{i}. {secret['type']} - {secret['severity'].upper()}\n"
                result += f"   {secret['description']}\n\n"
        else:
            result = "✅ No secrets detected. Text is safe!"
        
        return [TextContent(type="text", text=result)]
    
    async def get_stats(self) -> list[TextContent]:
        """Get security statistics"""
        logs = self.logger.get_recent_logs(100)
        
        total = len(logs)
        blocked = sum(1 for log in logs if log['action'] == 'BLOCKED')
        secrets_found = sum(log['secrets_found'] for log in logs)
        
        result = "📊 TerminalGuard Security Statistics:\n\n"
        result += f"Total Operations: {total}\n"
        result += f"Blocked: {blocked}\n"
        result += f"Allowed: {total - blocked}\n"
        result += f"Secrets Detected: {secrets_found}\n"
        result += f"Block Rate: {(blocked/total*100):.1f}%" if total > 0 else "Block Rate: 0%"
        
        return [TextContent(type="text", text=result)]
    
    async def run(self):
        """Run the middleware server"""
        try:
            print("[MIDDLEWARE] Starting middleware...", file=sys.stderr)
            
            # Connect to target server FIRST
            await self.connect_to_target_server()
            
            print("[MIDDLEWARE] Setting up handlers...", file=sys.stderr)
            
            # Setup handlers AFTER connecting
            self.setup_handlers()
            
            print("[MIDDLEWARE] Starting MCP server...", file=sys.stderr)
            
            # Run our middleware server
            async with stdio_server() as (read_stream, write_stream):
                print("[MIDDLEWARE] Server running, waiting for requests...", file=sys.stderr)
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options()
                )
        
        except Exception as e:
            print(f"[MIDDLEWARE] Fatal error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise
        
        finally:
            print("[MIDDLEWARE] Cleaning up...", file=sys.stderr)
            # Always cleanup
            await self.cleanup()

async def main():
    try:
        print("[MIDDLEWARE] Program starting...", file=sys.stderr)
        import os
        current_dir = os.path.dirname(os.path.abspath(__file__))
        target_script = os.path.join(current_dir, "test_email_server.py")
        
        middleware = TerminalGuardMiddleware(
            target_server_command=sys.executable,
            target_server_args=[target_script]
        )
        await middleware.run()
        
        # CRITICAL: Keep the middleware running indefinitely
        print("[MIDDLEWARE] Server started, running indefinitely...", file=sys.stderr)
        await asyncio.Event().wait()  # This keeps it alive forever
        
    except Exception as e:
        print(f"[MIDDLEWARE] Main error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

