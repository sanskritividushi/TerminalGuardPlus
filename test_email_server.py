import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("simulated-workspace-server")


# ============================================================
# Tool definitions — each represents a real-world attack surface
# ============================================================

TOOLS = [
    # --- Communication ---
    Tool(
        name="send_email",
        description="Send an email to a recipient",
        inputSchema={
            "type": "object",
            "properties": {
                "to":      {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject"},
                "body":    {"type": "string", "description": "Email body content"},
            },
            "required": ["to", "subject", "body"],
        },
    ),
    Tool(
        name="read_inbox",
        description="Read emails from inbox",
        inputSchema={
            "type": "object",
            "properties": {
                "count": {"type": "integer", "description": "Number of emails to read", "default": 5},
            },
        },
    ),
    Tool(
        name="send_slack_message",
        description="Send a message to a Slack channel or user",
        inputSchema={
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Slack channel name or user ID"},
                "message": {"type": "string", "description": "Message content"},
            },
            "required": ["channel", "message"],
        },
    ),

    # --- File Operations ---
    Tool(
        name="write_file",
        description="Write content to a file on the server",
        inputSchema={
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "File path to write to"},
                "content": {"type": "string", "description": "File content"},
            },
            "required": ["path", "content"],
        },
    ),
    Tool(
        name="read_file",
        description="Read content from a file on the server",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    ),

    # --- Database ---
    Tool(
        name="execute_sql",
        description="Execute a SQL query against the database",
        inputSchema={
            "type": "object",
            "properties": {
                "connection_string": {"type": "string", "description": "Database connection string"},
                "query":             {"type": "string", "description": "SQL query to execute"},
            },
            "required": ["connection_string", "query"],
        },
    ),

    # --- Cloud / DevOps ---
    Tool(
        name="deploy_service",
        description="Deploy a service to the cloud environment",
        inputSchema={
            "type": "object",
            "properties": {
                "service_name": {"type": "string", "description": "Name of the service to deploy"},
                "environment":  {"type": "string", "description": "Target environment (staging/production)"},
                "config":       {"type": "string", "description": "Deployment configuration or env vars"},
            },
            "required": ["service_name", "environment", "config"],
        },
    ),
    Tool(
        name="run_shell_command",
        description="Execute a shell command on the remote server",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
            },
            "required": ["command"],
        },
    ),

    # --- API / HTTP ---
    Tool(
        name="http_request",
        description="Make an HTTP request to an external API",
        inputSchema={
            "type": "object",
            "properties": {
                "method":  {"type": "string", "description": "HTTP method (GET, POST, PUT, DELETE)"},
                "url":     {"type": "string", "description": "Request URL"},
                "headers": {"type": "string", "description": "Request headers as JSON string"},
                "body":    {"type": "string", "description": "Request body"},
            },
            "required": ["method", "url"],
        },
    ),

    # --- Secret / Vault Management ---
    Tool(
        name="store_secret",
        description="Store a secret in the vault",
        inputSchema={
            "type": "object",
            "properties": {
                "key":   {"type": "string", "description": "Secret key name"},
                "value": {"type": "string", "description": "Secret value"},
            },
            "required": ["key", "value"],
        },
    ),

    # --- Code / Git ---
    Tool(
        name="create_github_issue",
        description="Create a new issue on a GitHub repository",
        inputSchema={
            "type": "object",
            "properties": {
                "repo":  {"type": "string", "description": "Repository in owner/repo format"},
                "title": {"type": "string", "description": "Issue title"},
                "body":  {"type": "string", "description": "Issue body / description"},
            },
            "required": ["repo", "title", "body"],
        },
    ),
    Tool(
        name="commit_and_push",
        description="Commit changes and push to a remote Git repository",
        inputSchema={
            "type": "object",
            "properties": {
                "repo_url": {"type": "string", "description": "Remote repository URL"},
                "message":  {"type": "string", "description": "Commit message"},
                "files":    {"type": "string", "description": "Comma-separated list of file paths"},
            },
            "required": ["repo_url", "message", "files"],
        },
    ),

    # --- Notes / Documents ---
    Tool(
        name="create_note",
        description="Create a note or document in the workspace",
        inputSchema={
            "type": "object",
            "properties": {
                "title":   {"type": "string", "description": "Note title"},
                "content": {"type": "string", "description": "Note content (markdown supported)"},
            },
            "required": ["title", "content"],
        },
    ),
]


# ============================================================
# Tool handlers — all simulated (no real side effects)
# ============================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    # --- Communication ---
    if name == "send_email":
        return [TextContent(type="text", text=(
            f"✉️ Email Sent!\n"
            f"To: {arguments.get('to')}\n"
            f"Subject: {arguments.get('subject')}\n"
            f"Body: {arguments.get('body')}"
        ))]

    if name == "read_inbox":
        count = arguments.get("count", 5)
        return [TextContent(type="text", text=(
            f"📬 Inbox ({count} most recent):\n"
            "1. Welcome to our service\n"
            "2. Your account verification\n"
            "3. Newsletter — April 2026\n"
        ))]

    if name == "send_slack_message":
        return [TextContent(type="text", text=(
            f"💬 Slack message sent to #{arguments.get('channel')}:\n"
            f"{arguments.get('message')}"
        ))]

    # --- File Operations ---
    if name == "write_file":
        return [TextContent(type="text", text=(
            f"📝 File written: {arguments.get('path')}\n"
            f"Size: {len(arguments.get('content', ''))} chars"
        ))]

    if name == "read_file":
        return [TextContent(type="text", text=(
            f"📄 Contents of {arguments.get('path')}:\n"
            "# Sample config\nDEBUG=true\nPORT=8080"
        ))]

    # --- Database ---
    if name == "execute_sql":
        return [TextContent(type="text", text=(
            f"🗄️ SQL executed on {arguments.get('connection_string', '')[:40]}...\n"
            f"Query: {arguments.get('query')}\n"
            "Result: 3 rows returned"
        ))]

    # --- Cloud / DevOps ---
    if name == "deploy_service":
        return [TextContent(type="text", text=(
            f"🚀 Deployed {arguments.get('service_name')} to {arguments.get('environment')}\n"
            f"Config: {arguments.get('config', '')[:80]}"
        ))]

    if name == "run_shell_command":
        return [TextContent(type="text", text=(
            f"🖥️ Command executed: {arguments.get('command')}\n"
            "Exit code: 0\nOutput: OK"
        ))]

    # --- API / HTTP ---
    if name == "http_request":
        return [TextContent(type="text", text=(
            f"🌐 {arguments.get('method')} {arguments.get('url')}\n"
            "Status: 200 OK\nBody: {\"success\": true}"
        ))]

    # --- Vault ---
    if name == "store_secret":
        return [TextContent(type="text", text=(
            f"🔐 Secret stored: {arguments.get('key')} = ****"
        ))]

    # --- Git ---
    if name == "create_github_issue":
        return [TextContent(type="text", text=(
            f"🐛 Issue created on {arguments.get('repo')}:\n"
            f"Title: {arguments.get('title')}\n"
            f"Body: {arguments.get('body', '')[:100]}"
        ))]

    if name == "commit_and_push":
        return [TextContent(type="text", text=(
            f"📦 Pushed to {arguments.get('repo_url')}\n"
            f"Message: {arguments.get('message')}\n"
            f"Files: {arguments.get('files')}"
        ))]

    # --- Notes ---
    if name == "create_note":
        return [TextContent(type="text", text=(
            f"📒 Note created: {arguments.get('title')}\n"
            f"Content: {arguments.get('content', '')[:100]}"
        ))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


# ============================================================
# Entry point
# ============================================================

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )

if __name__ == "__main__":
    asyncio.run(main())
