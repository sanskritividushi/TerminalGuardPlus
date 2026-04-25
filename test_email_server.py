import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("simple-email-server")

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools"""
    return [
        Tool(
            name="send_email",
            description="Send an email to a recipient",
            inputSchema={
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Recipient email address"
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject"
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body content"
                    }
                },
                "required": ["to", "subject", "body"]
            }
        ),
        Tool(
            name="read_inbox",
            description="Read emails from inbox",
            inputSchema={
                "type": "object",
                "properties": {
                    "count": {
                        "type": "integer",
                        "description": "Number of emails to read",
                        "default": 5
                    }
                }
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls"""
    
    if name == "send_email":
        to = arguments.get("to", "")
        subject = arguments.get("subject", "")
        body = arguments.get("body", "")
        
        result = f"✉️ Email Successfully Sent!\n\n"
        result += f"To: {to}\n"
        result += f"Subject: {subject}\n"
        result += f"Body: {body}\n"
        
        return [TextContent(type="text", text=result)]
    
    elif name == "read_inbox":
        count = arguments.get("count", 5)
        result = f"📬 Inbox ({count} most recent emails):\n\n"
        result += "1. Welcome to our service\n"
        result += "2. Your account verification\n"
        result += "3. Newsletter - October 2025\n"
        
        return [TextContent(type="text", text=result)]
    
    return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Run the email server"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
