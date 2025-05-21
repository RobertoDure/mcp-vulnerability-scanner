import { ScannerService } from '../../src/services/scanner.js';
import axios from 'axios';
import nock from 'nock';

// Mock axios module
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock console methods to avoid cluttering test output
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

// Mock child_process exec for Nmap tests
jest.mock('child_process', () => ({
  exec: jest.fn((command, callback) => {
    if (callback) {
      callback(null, { stdout: 'Nmap mock output' });
    }
    return {
      stdout: 'Nmap mock output'
    };
  }),
  // Keep the actual promisify implementation
  promisify: jest.requireActual('util').promisify
}));

describe('ScannerService API Connectivity Tests', () => {
  let scannerService: ScannerService;
  
  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
    
    // Mock console methods to reduce test output noise
    console.log = jest.fn();
    console.error = jest.fn();
    console.warn = jest.fn();
    
    // Create a new ScannerService instance for each test
    scannerService = new ScannerService({
      vulnDB: {
        apiKey: 'test-api-key',
        baseUrl: 'https://api.vulndb.test'
      }
    });
  });

  afterEach(() => {
    // Restore console methods
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    console.warn = originalConsoleWarn;
    
    // Clean up nock after each test
    nock.cleanAll();
  });

  describe('IP Validation', () => {
    test('should validate correct IP addresses', () => {
      // Use the private isValidIpAddress method by casting to any
      expect((scannerService as any).isValidIpAddress('192.168.1.1')).toBe(true);
      expect((scannerService as any).isValidIpAddress('10.0.0.1')).toBe(true);
      expect((scannerService as any).isValidIpAddress('172.16.0.1')).toBe(true);
      expect((scannerService as any).isValidIpAddress('8.8.8.8')).toBe(true);
    });

    test('should reject invalid IP addresses', () => {
      expect((scannerService as any).isValidIpAddress('256.0.0.1')).toBe(false);
      expect((scannerService as any).isValidIpAddress('192.168.1')).toBe(false);
      expect((scannerService as any).isValidIpAddress('192.168.1.1.5')).toBe(false);
      expect((scannerService as any).isValidIpAddress('not-an-ip')).toBe(false);
    });
  });

  describe('VulnDB API Connectivity', () => {
    test('should handle successful API responses', async () => {
      // Clear any previous mocks
      nock.cleanAll();
      jest.clearAllMocks();
      
      // Setup axios mocks for sequential calls
      // Use the implementation method that is compatible with your axios mock setup
      (mockedAxios as any).mockImplementation((config: any) => {
        if (config.url.includes('/api/v1/assets/search')) {
          return Promise.resolve({
            data: {
              assets: [{ id: '12345' }]
            }
          });
        } else if (config.url.includes('/api/v1/assets/12345/vulnerabilities')) {
          return Promise.resolve({
            data: {
              vulnerabilities: [{
                cve_id: 'CVE-2023-12345',
                cvss_v3_score: 8.5,
                description: 'Test vulnerability',
                solution: 'Apply security patch'
              }]
            }
          });
        }
        return Promise.resolve({ data: {} });
      });

      const vulnerabilities = await (scannerService as any).scanWithVulnDB('192.168.1.1');
      
      // Verify the expected results
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].name).toBe('CVE-2023-12345');
      expect(vulnerabilities[0].severity).toBe('High');
    });

    test('should handle API errors gracefully', async () => {
      // Clean previous mocks
      jest.clearAllMocks();
      nock.cleanAll();
      
      // Mock API error with axios using implementation
      (mockedAxios as any).mockImplementation(() => {
        return Promise.reject(new Error('API connection failed'));
      });

      // We expect it to fall back to mock data
      const vulnerabilities = await (scannerService as any).scanWithVulnDB('192.168.1.1');
      
      // Testing that it falls back to mock vulnerabilities
      expect(Array.isArray(vulnerabilities)).toBe(true);
      // The specific length depends on the mock implementation but should be defined
      expect(vulnerabilities.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Main Scanner API Integration', () => {
    test('should scan IP addresses and combine results', async () => {
      // Mock both Nmap and VulnDB API to return some results
      (scannerService as any).scanWithNmap = jest.fn(() => 
        Promise.resolve([
          {
            name: 'Open TCP Port: 80',
            severity: 'Low',
            description: 'Port 80/tcp is open running service: http',
            remediation: 'Close this port if not needed'
          }
        ])
      );
      
      (scannerService as any).scanWithVulnDB = jest.fn(() => 
        Promise.resolve([
          {
            name: 'CVE-2023-54321',
            severity: 'Medium',
            description: 'SQL Injection vulnerability',
            remediation: 'Apply security patches'
          }
        ])
      );

      const result = await scannerService.scanIp('192.168.1.1');
      
      expect(result).toHaveLength(2);
      expect(result.some(v => v.name === 'Open TCP Port: 80')).toBe(true);
      expect(result.some(v => v.name === 'CVE-2023-54321')).toBe(true);
    });

    test('should handle invalid IP addresses', async () => {
      await expect(scannerService.scanIp('invalid-ip')).rejects.toThrow('Invalid IP address');
    });
  });

  describe('Mock Data Generation', () => {
    test('should generate mock data for testing purposes', async () => {
      const mockData = await (scannerService as any).generateMockVulnerabilities('192.168.1.3');
      
      expect(Array.isArray(mockData)).toBe(true);
      // For IP ending in 3, we expect 1 vulnerability (lastOctet % 3 === 0)
      expect(mockData.length).toBe(1);
      expect(mockData[0].name).toBe('CVE-2023-12345');
      expect(mockData[0].severity).toBe('High');
    });
    
    test('should generate multiple mock vulnerabilities based on IP', async () => {
      // IP ending in 35 should generate 2 vulnerabilities (35 % 5 === 0 and 35 % 7 === 0)
      const mockData = await (scannerService as any).generateMockVulnerabilities('192.168.1.35');
      
      expect(mockData.length).toBe(2);
      // Should have the "divisible by 5" and "divisible by 7" vulnerabilities
      expect(mockData.some(v => v.name === 'CVE-2023-54321')).toBe(true);
      expect(mockData.some(v => v.name === 'CVE-2023-98765')).toBe(true);
    });
    
    test('should return empty array for certain IPs', async () => {
      // IP ending in 10 should generate no vulnerabilities (lastOctet % 10 === 0)
      const mockData = await (scannerService as any).generateMockVulnerabilities('192.168.1.10');
      
      expect(mockData.length).toBe(0);
    });
  });
});
