import axios from 'axios';
import nock from 'nock';
import { ScannerService, VulnDBConfig } from '../../src/services/scanner.js';

describe('VulnDB API Connectivity Tests', () => {
  const baseUrl = 'https://api.vulndb.test';
  const apiKey = 'test-api-key';
  
  let scannerService: ScannerService;

  beforeEach(() => {
    // Clear all previous nock interceptors
    nock.cleanAll();
    
    // Initialize the scanner service with VulnDB config
    const vulnDBConfig: VulnDBConfig = {
      apiKey,
      baseUrl
    };
    
    scannerService = new ScannerService({ vulnDB: vulnDBConfig });
  });

  afterAll(() => {
    // Ensure all nock interceptors are removed
    nock.restore();
  });

  test('API connection succeeds with valid credentials', async () => {
    // Mock the assets search endpoint
    nock(baseUrl)
      .get('/api/v1/assets/search')
      .query({ ip_address: '192.168.1.1' })
      .reply(200, {
        assets: [{ id: 'asset123' }]
      });
    
    // Mock the vulnerabilities endpoint
    nock(baseUrl)
      .get('/api/v1/assets/asset123/vulnerabilities')
      .reply(200, {
        vulnerabilities: [
          {
            cve_id: 'CVE-2023-12345',
            title: 'Test Vulnerability',
            cvss_v3_score: 7.5,
            description: 'This is a test vulnerability',
            solution: 'Apply security patch'
          }
        ]
      });

    // Use the private scanWithVulnDB method via type casting
    const result = await (scannerService as any).scanWithVulnDB('192.168.1.1');
    
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('CVE-2023-12345');
    expect(result[0].severity).toBe('High'); // Based on CVSS score 7.5
    expect(result[0].description).toBe('This is a test vulnerability');
    expect(result[0].remediation).toBe('Apply security patch');
  });

  test('API connection fails with network error', async () => {
    // Mock a network failure
    nock(baseUrl)
      .get('/api/v1/assets/search')
      .query({ ip_address: '192.168.1.1' })
      .replyWithError('Network connection failed');

    // Spy on console.error to verify it's called
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
    
    // Call the method and verify it falls back to mock data
    const result = await (scannerService as any).scanWithVulnDB('192.168.1.1');
    
    // Verify console.error was called with an error message
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      'Error querying VulnDB API:',
      expect.any(Error)
    );
    
    // Verify that mock data was returned
    expect(Array.isArray(result)).toBe(true);
    
    consoleErrorSpy.mockRestore();
  });

  test('API returns no vulnerabilities for an IP', async () => {
    // Mock the assets search endpoint - no assets found
    nock(baseUrl)
      .get('/api/v1/assets/search')
      .query({ ip_address: '192.168.1.1' })
      .reply(200, {
        assets: []
      });

    const result = await (scannerService as any).scanWithVulnDB('192.168.1.1');
    
    expect(result).toHaveLength(0);
  });

  test('API authentication failure', async () => {
    // Mock an authentication failure
    nock(baseUrl)
      .get('/api/v1/assets/search')
      .query({ ip_address: '192.168.1.1' })
      .reply(401, { error: 'Unauthorized', message: 'Invalid API key' });

    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
    
    const result = await (scannerService as any).scanWithVulnDB('192.168.1.1');
    
    // Verify console.error was called with an error message
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      'Error querying VulnDB API:',
      expect.any(Error)
    );
    
    // Verify that mock data was returned
    expect(Array.isArray(result)).toBe(true);
    
    consoleErrorSpy.mockRestore();
  });

  test('Multiple vulnerabilities are processed correctly', async () => {
    // Mock the assets search endpoint
    nock(baseUrl)
      .get('/api/v1/assets/search')
      .query({ ip_address: '192.168.1.1' })
      .reply(200, {
        assets: [{ id: 'asset123' }]
      });
    
    // Mock the vulnerabilities endpoint with multiple vulnerabilities
    nock(baseUrl)
      .get('/api/v1/assets/asset123/vulnerabilities')
      .reply(200, {
        vulnerabilities: [
          {
            cve_id: 'CVE-2023-12345',
            cvss_v3_score: 9.5,
            description: 'Critical vulnerability',
            solution: 'Apply security patch'
          },
          {
            cve_id: 'CVE-2023-54321',
            cvss_v3_score: 5.5,
            description: 'Medium vulnerability',
            remediation: 'Update configuration'
          },
          {
            vulndb_id: '98765',
            // Removed title so that VulnDB-98765 will be used as the name
            cvss_v2_score: 3.2,
            short_description: 'Low priority issue',
            solution: 'Optional fix'
          }
        ]
      });

    // Call the method and verify the results
    const result = await (scannerService as any).scanWithVulnDB('192.168.1.1');
    
    expect(result).toHaveLength(3);
    
    // Check first vulnerability (Critical)
    expect(result[0].name).toBe('CVE-2023-12345');
    expect(result[0].severity).toBe('Critical'); // Based on CVSS score 9.5
    expect(result[0].remediation).toBe('Apply security patch');
    
    // Check second vulnerability (Medium)
    expect(result[1].name).toBe('CVE-2023-54321');
    expect(result[1].severity).toBe('Medium'); // Based on CVSS score 5.5
    expect(result[1].remediation).toBe('Update configuration');
    
    // Check third vulnerability (Low)
    expect(result[2].name).toBe('VulnDB-98765');
    expect(result[2].severity).toBe('Low'); // Based on CVSS score 3.2
    expect(result[2].description).toBe('Low priority issue');
    expect(result[2].remediation).toBe('Optional fix');
  });
});
