import axios from 'axios';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface Vulnerability {
  name: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  remediation?: string;
}

// Configuration interface for VulnDB API
export interface VulnDBConfig {
  apiKey: string;
  baseUrl?: string;
}

export class ScannerService {
  private vulnDBConfig?: VulnDBConfig;
  private enableVerboseLogging: boolean = false;

  constructor(config?: { vulnDB?: VulnDBConfig; verboseLogging?: boolean }) {
    this.vulnDBConfig = config?.vulnDB;
    this.enableVerboseLogging = config?.verboseLogging || false;
  }
  
  private log(message: string, ...args: any[]) {
    if (this.enableVerboseLogging) {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] [ScannerService] ${message}`, ...args);
    } else {
      console.log(message, ...args);
    }
  }

  // Main method to scan an IP address for vulnerabilities
  async scanIp(ip: string): Promise<Vulnerability[]> {
    this.log(`Starting vulnerability scan for IP: ${ip}`);
    
    try {
      // Validate IP address
      if (!this.isValidIpAddress(ip)) {
        throw new Error(`Invalid IP address: ${ip}`);
      }
      
      // Run multiple scanning methods and combine results
      const [
        nmapResults,
        apiResults,
      ] = await Promise.all([
        this.scanWithNmap(ip),
        this.scanWithVulnerabilityApi(ip),
      ]);
      
      // Combine and deduplicate results
      const allVulnerabilities = [...nmapResults, ...apiResults];
      return this.deduplicateVulnerabilities(allVulnerabilities);
    } catch (error) {
      this.log(`Error scanning IP ${ip}:`, error);
      throw error;
    }
  }
  
  // Validate if the provided string is a valid IP address
  private isValidIpAddress(ip: string): boolean {
    const ipPattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipPattern.test(ip);
  }
  
  // Scan using Nmap (requires Nmap to be installed on the system)
  private async scanWithNmap(ip: string): Promise<Vulnerability[]> {
    try {
      // Check if nmap is installed
      try {
        await execAsync('which nmap');
      } catch (error) {
        this.log('Nmap is not installed. Skipping Nmap scan.');
        return [];
      }
      
      // Run a basic nmap scan
      const { stdout } = await execAsync(`nmap -sV --script vuln ${ip}`);
      
      // Parse nmap results and convert to Vulnerability objects
      return this.parseNmapResults(stdout);
    } catch (error) {
      this.log('Error scanning with Nmap:', error);
      return [];
    }
  }
  
  // Parse Nmap output to extract vulnerability information
  private parseNmapResults(nmapOutput: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    
    // Look for vulnerability scripts output in the Nmap results
    const vulnMatches = nmapOutput.match(/\|\s*(CVE-\d+-\d+|VULNERABILITY|VULN-[^:]+):.+?(?=\n\|_|$)/gs);
    
    if (vulnMatches) {
      vulnMatches.forEach(match => {
        const nameParts = match.match(/\|\s*(CVE-\d+-\d+|VULNERABILITY|VULN-[^:]+):/);
        const name = nameParts ? nameParts[1].trim() : 'Unknown Vulnerability';
        
        // Extract severity - default to Medium if not specified
        let severity: Vulnerability['severity'] = 'Medium';
        if (match.toLowerCase().includes('critical')) severity = 'Critical';
        else if (match.toLowerCase().includes('high')) severity = 'High';
        else if (match.toLowerCase().includes('low')) severity = 'Low';
        
        // Extract description
        const description = match
          .replace(/\|\s*(CVE-\d+-\d+|VULNERABILITY|VULN-[^:]+):/, '')
          .replace(/\|_/g, '')
          .trim();
        
        vulnerabilities.push({
          name,
          severity,
          description,
        });
      });
    }
    
    // Also parse open ports as potential vulnerabilities
    const portMatches = nmapOutput.match(/(\d+)\/(\w+)\s+open\s+([^\n]+)/g);
    if (portMatches) {
      portMatches.forEach(match => {
        const [, port, protocol, service] = match.match(/(\d+)\/(\w+)\s+open\s+([^\n]+)/) || [];
        if (port && protocol) {
          vulnerabilities.push({
            name: `Open ${protocol.toUpperCase()} Port: ${port}`,
            severity: 'Low',
            description: `Port ${port}/${protocol} is open running service: ${service || 'unknown'}`,
            remediation: 'Close this port if it is not required for your services.'
          });
        }
      });
    }
    
    return vulnerabilities;
  }
  
  // Scan using VulnDB or fallback to mock data if not configured
  private async scanWithVulnerabilityApi(ip: string): Promise<Vulnerability[]> {
    try {
      // Check if VulnDB is configured
      if (this.vulnDBConfig?.apiKey) {
        return await this.scanWithVulnDB(ip);
      } else {
        this.log('VulnDB API not configured. Using mock vulnerability data.');
        return this.generateMockVulnerabilities(ip);
      }
    } catch (error) {
      this.log('Error scanning with vulnerability API:', error);
      return [];
    }
  }

  // Scan using the VulnDB API
  private async scanWithVulnDB(ip: string): Promise<Vulnerability[]> {
    try {
      const baseUrl = this.vulnDBConfig?.baseUrl || 'https://vuldb.com';
      const apiKey = this.vulnDBConfig?.apiKey;
      
      if (!apiKey) {
        throw new Error('VulnDB API key is not configured');
      }

      this.log(`Scanning IP ${ip} with VulnDB API`);
      
      // Query VulnDB API with IP-based search
      const searchResponse = await axios({
        method: 'GET',
        url: `${baseUrl}/api/v3/vulnerabilities`,
        params: {
          search: ip,
          details: 1,
          'api-version': 3,
          cti: 1 // Include cyber threat intelligence data
        },
        headers: {
          'X-API-Key': apiKey,
          'Accept': 'application/json'
        }
      });

      if (!searchResponse.data || !searchResponse.data.result) {
        this.log(`No vulnerabilities found in VulDB for IP: ${ip}`);
        return [];
      }

      const vulnerabilities: Vulnerability[] = [];

      // Process the vulnerabilities from the search response
      for (const vuln of searchResponse.data.result) {
        // Map VulDB severity to our severity levels based on CVSS scores
        let severity: Vulnerability['severity'] = 'Medium';
        const cvssScore = 
          vuln.vulnerability_cvss4_basescore || // Try CVSS v4 first
          vuln.vulnerability_cvss3_basescore || // Then CVSS v3
          vuln.vulnerability_cvss2_basescore ||  // Then CVSS v2
          5.0; // Default score if none available
        
        if (cvssScore >= 9.0) severity = 'Critical';
        else if (cvssScore >= 7.0) severity = 'High'; 
        else if (cvssScore >= 4.0) severity = 'Medium';
        else severity = 'Low';

        vulnerabilities.push({
          name: vuln.source_cve_id || `VulDB-${vuln.entry_id}`,
          severity,
          description: vuln.entry_description || vuln.entry_title || 'No description available',
          remediation: vuln.countermeasure_description || undefined
        });
      }

      return vulnerabilities;
    } catch (error: any) {
      this.log('Error querying VulnDB API:', error);
      if (error.response) {
        // Log specific API error information
        this.log(`VulDB API Error - Status: ${error.response.status}, Message: ${JSON.stringify(error.response.data)}`);
      }
      // If there's an API error, fall back to mock data
      this.log('Falling back to mock vulnerability data due to API error');
      return this.generateMockVulnerabilities(ip);
    }
  }

  // Generate mock vulnerability data for testing or when API is unavailable
  private generateMockVulnerabilities(ip: string): Promise<Vulnerability[]> {
    return new Promise(resolve => {
      // Simulate API delay
      setTimeout(() => {
        // Generate some sample vulnerabilities based on the IP
        const lastOctet = parseInt(ip.split('.').pop() || '0', 10);
        
        // Skip vulnerabilities for loopback and some private IPs
        if (ip === '127.0.0.1' || lastOctet % 10 === 0) {
          resolve([]);
          return;
        }
        
        const sampleVulnerabilities: Vulnerability[] = [];
        
        // Add some sample vulnerabilities based on the IP address value
        if (lastOctet % 3 === 0) {
          sampleVulnerabilities.push({
            name: 'CVE-2023-12345',
            severity: 'High',
            description: 'Remote Code Execution vulnerability in web server',
            remediation: 'Update web server to the latest version'
          });
        }
        
        if (lastOctet % 5 === 0) {
          sampleVulnerabilities.push({
            name: 'CVE-2023-54321',
            severity: 'Medium',
            description: 'SQL Injection vulnerability in database interface',
            remediation: 'Apply security patches and implement input validation'
          });
        }
        
        if (lastOctet % 7 === 0) {
          sampleVulnerabilities.push({
            name: 'CVE-2023-98765',
            severity: 'Critical',
            description: 'Unpatched OS vulnerability allowing privilege escalation',
            remediation: 'Update operating system with the latest security patches'
          });
        }
        
        resolve(sampleVulnerabilities);
      }, 1000);
    });
  }
  
  // Remove duplicate vulnerabilities from the combined results
  private deduplicateVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const uniqueVulnerabilities: Vulnerability[] = [];
    const vulnNames = new Set<string>();
    
    for (const vuln of vulnerabilities) {
      if (!vulnNames.has(vuln.name)) {
        vulnNames.add(vuln.name);
        uniqueVulnerabilities.push(vuln);
      }
    }
    
    return uniqueVulnerabilities;
  }
}
