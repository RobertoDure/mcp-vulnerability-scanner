# MCP Vulnerability Scanner

A Model Context Protocol (MCP) server for scanning IP addresses for vulnerabilities. This server provides tools to perform security scanning on individual IPs or multiple IPs at once.

## Features

- Scan IP addresses for vulnerabilities using multiple methods:
  - Nmap vulnerability scanning
  - API-based vulnerability checks
- Supports single IP scanning or batch scanning of multiple IPs
- Returns detailed reports with vulnerability severity, descriptions, and remediation steps
- Implements the Model Context Protocol for easy integration with MCP clients

## Prerequisites

- Node.js (v14.x or higher)
- npm (v7.x or higher)
- Nmap (optional, for enhanced scanning capabilities)

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd mcp-vulnerability-scanner
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Install Nmap (optional but recommended):
   ```bash
   # For Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install nmap
   
   # For CentOS/RHEL
   sudo yum install nmap
   
   # For macOS
   brew install nmap
   ```

## Configuration

The MCP Vulnerability Scanner is configured through the following files:

### 1. `.mcp.json`

This is the main MCP configuration file:

```json
{
  "name": "vulnerability-scanner",
  "version": "1.0.0",
  "description": "An MCP server for scanning vulnerabilities on IP addresses",
  "command": "npm",
  "args": ["run", "dev"],
  "capabilities": {
    "contextItemTypes": ["ip"]
  }
}
```

### 2. Integration with VS Code

For VS Code integration, the configuration is in `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "mcp_vuln": {
      "command": "npm",
      "args": [
        "run",
        "dev",
        "mcp-vulnerability-scanner",
        "--prefix",
        "/path/to/mcp-vulnerability-scanner"
      ],
      "env": {
        "MCP_SERVER_PORT": "3000"
      }
    }
  }
}
```

Update the `--prefix` path to point to your installation location.

## Usage Example

Below is a example showing the vulnerability scanner in action:

* Single Ip Addess scan

![Vulnerability Scanner Screenshot](docs/scan-ip.png)

* Multiple Ip Addess scan

![Vulnerability Scanner Screenshot](docs/scan-multiple-ips.png)

## Available Tools

This MCP server provides the following tools:

### 1. `scan-ip`

Scans a single IP address for vulnerabilities.

**Parameters:**
- `ip`: The IP address to scan (string)

**Example usage:**
```
scan-ip 192.168.1.1
```

### 2. `scan-multiple-ips`

Scans multiple IP addresses for vulnerabilities.

**Parameters:**
- `ips`: Array of IP addresses to scan (string[])

**Example usage:**
```
scan-multiple-ips ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
```

## Deployment Options

### 1. Local Development

Run the server in development mode:

```bash
npm run dev
```

### 2. Build and Run in Production

```bash
npm run build
npm start
```

### 3. Docker Deployment

Create a Dockerfile in the project root:

```dockerfile
FROM node:18-alpine

# Install Nmap
RUN apk add --no-cache nmap

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
```

Build and run the Docker container:

```bash
docker build -t mcp-vulnerability-scanner .
docker run -p 3000:3000 mcp-vulnerability-scanner
```

### 4. VS Code Extension Integration

To use this server in VS Code:

1. Configure the `.vscode/mcp.json` file as shown above
2. Ensure the path to the server is correctly set
3. The server will be available to MCP-enabled extensions

## Security Considerations

- This scanner requires administrative/root permissions to run comprehensive Nmap scans
- Only scan IP addresses that you have permission to scan
- Be aware that vulnerability scanning might trigger security systems or IDS alerts
- The scan results are provided for informational purposes only

## License

MIT
