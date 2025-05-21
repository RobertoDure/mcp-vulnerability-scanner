// Import from MCP SDK following the recommended pattern from the documentation
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ScannerService, VulnDBConfig } from './services/scanner.js';
import { Vulnerability } from './services/scanner.js';
import { z } from 'zod';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Define interface for scan result
interface ScanResult {
  ip: string;
  vulnerabilities: Vulnerability[];
}

async function main() {
  try {
    // Initialize the MCP server
    const server = new McpServer({
      name: 'vulnerability-scanner',
      version: '1.0.0',
    }, {
      capabilities: {
        contextItemTypes: ['ip']
      }
    });

    // Load VulnDB configuration from environment variables
    const vulnDBConfig: VulnDBConfig | undefined = process.env.VULNDB_API_KEY ? {
      apiKey: process.env.VULNDB_API_KEY,
      baseUrl: process.env.VULNDB_BASE_URL
    } : undefined;

    // Initialize scanner service with VulnDB config and verbose logging enabled
    const scannerService = new ScannerService({
      vulnDB: vulnDBConfig,
      verboseLogging: true // Enable detailed logging with timestamps
    });

    if (vulnDBConfig?.apiKey) {
      process.stdout.write(`[${new Date().toISOString()}] VulnDB API configured and ready\n`);
    } else {
      process.stdout.write(`[${new Date().toISOString()}] WARNING: VulnDB API not configured. Will use mock vulnerability data.\n`);
      process.stdout.write(`[${new Date().toISOString()}] WARNING: Set VULNDB_API_KEY environment variable to enable VulnDB integration.\n`);
    }

    // Register a vulnerability scanning tool
    server.tool(
      "scan-ip",
      {
        ip: z.string().describe("The IP address to scan for vulnerabilities")
      },
      async ({ ip }) => {
        process.stdout.write(`[${new Date().toISOString()}] Starting scan for IP: ${ip}\n`);
        try {
          const vulnerabilities = await scannerService.scanIp(ip);
          // Format results as markdown
          let responseText = `# Vulnerability Scan Results for ${ip}\n\n`;
          
          if (vulnerabilities.length === 0) {
            responseText += 'No vulnerabilities found.\n\n';
          } else {
            responseText += 'Found vulnerabilities:\n\n';
            
            vulnerabilities.forEach((vuln: Vulnerability, index: number) => {
              responseText += `## ${index + 1}. ${vuln.name}\n\n`;
              responseText += `- **Severity**: ${vuln.severity}\n`;
              responseText += `- **Description**: ${vuln.description}\n`;
              if (vuln.remediation) {
                responseText += `- **Remediation**: ${vuln.remediation}\n`;
              }
              responseText += '\n';
            });
          }
          
          return {
            content: [
              { 
                type: "text", 
                text: responseText 
              }
            ]
          };
        } catch (error: unknown) {
          process.stderr.write(`[${new Date().toISOString()}] Error scanning IP: ${error}\n`);
          return {
            content: [
              { 
                type: "text", 
                text: `Error scanning IP: ${error instanceof Error ? error.message : String(error)}` 
              }
            ],
            isError: true
          };
        }
      }
    );

    // Register a bulk scanning tool for multiple IPs
    server.tool(
      "scan-multiple-ips",
      {
        ips: z.array(z.string()).describe("Array of IP addresses to scan for vulnerabilities")
      },
      async ({ ips }) => {
        process.stdout.write(`[${new Date().toISOString()}] Scanning multiple IPs: ${ips.join(", ")}\n`);
        try {
          // Process each IP address
          const results = await Promise.all(
            ips.map(async (ip: string) => {
              process.stdout.write(`[${new Date().toISOString()}] Scanning IP: ${ip}\n`);
              const vulnerabilities = await scannerService.scanIp(ip);
              return { ip, vulnerabilities };
            })
          );
          
          // Format results as markdown
          let responseText = '# Vulnerability Scan Results\n\n';
          
          for (const result of results) {
            responseText += `## IP Address: ${result.ip}\n\n`;
            
            if (result.vulnerabilities.length === 0) {
              responseText += 'No vulnerabilities found.\n\n';
            } else {
              responseText += 'Found vulnerabilities:\n\n';
              
              result.vulnerabilities.forEach((vuln: Vulnerability, index: number) => {
                responseText += `### ${index + 1}. ${vuln.name}\n\n`;
                responseText += `- **Severity**: ${vuln.severity}\n`;
                responseText += `- **Description**: ${vuln.description}\n`;
                if (vuln.remediation) {
                  responseText += `- **Remediation**: ${vuln.remediation}\n`;
                }
                responseText += '\n';
              });
            }
          }
          
          return {
            content: [
              { 
                type: "text", 
                text: responseText 
              }
            ]
          };
        } catch (error: unknown) {
          console.error('Error scanning IPs:', error);
          return {
            content: [
              { 
                type: "text", 
                text: `Error scanning IPs: ${error instanceof Error ? error.message : String(error)}` 
              }
            ],
            isError: true
          };
        }
      }
    );

    // Create a transport for the server (stdio in this case)
    const transport = new StdioServerTransport();
    
    // Connect the server to the transport
    process.stdout.write(`[${new Date().toISOString()}] Starting Vulnerability Scanner MCP Server...\n`);
    await server.connect(transport);
    process.stdout.write(`[${new Date().toISOString()}] Vulnerability Scanner MCP Server started and ready\n`);
  } catch (error) {
    console.error('Failed to start MCP server:', error);
    process.exit(1);
  }
}

// Run the main function
main();
