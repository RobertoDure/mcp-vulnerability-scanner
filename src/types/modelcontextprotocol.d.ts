// This is a declaration file to help TypeScript find the MCP SDK
declare module '@modelcontextprotocol/sdk' {
  export class MCPServer {
    constructor(config: {
      name: string;
      version: string;
      options?: {
        capabilities?: {
          contextItemTypes?: string[];
        };
        debugMode?: boolean;
      };
    });
    
    onContextRequest(handler: (request: any) => Promise<{ text: string }>): void;
    
    listen(): void;
  }
}

// Also add support for subpaths
declare module '@modelcontextprotocol/sdk/server' {
  export { MCPServer } from '@modelcontextprotocol/sdk';
}

declare module '@modelcontextprotocol/sdk/index.js' {
  export { MCPServer } from '@modelcontextprotocol/sdk';
}

declare module '@modelcontextprotocol/sdk/dist/esm/server/index.js' {
  export { MCPServer } from '@modelcontextprotocol/sdk';
}

declare module '@modelcontextprotocol/sdk/dist/cjs/server/index.js' {
  export { MCPServer } from '@modelcontextprotocol/sdk';
}
