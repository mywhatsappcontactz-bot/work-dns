import http from 'node:http';
import { DeviceAuthenticator } from './auth.js';
import { DnsHandler } from './dns-handler.js';

export interface DohServerConfig {
  port: number;
  host?: string;
}

export class DohServer {
  private server: http.Server | null = null;
  private authenticator: DeviceAuthenticator;
  private handler: DnsHandler;

  constructor(authenticator: DeviceAuthenticator, handler: DnsHandler) {
    this.authenticator = authenticator;
    this.handler = handler;
  }

  public start(config: DohServerConfig): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res).catch((err) => {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal Server Error', message: err?.message }));
        });
      });

      this.server.on('error', (err) => reject(err));
      this.server.listen(config.port, config.host ?? '127.0.0.1', () => {
        resolve();
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

    // Health probe
    if (url.pathname === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'doh-gateway' }));
      return;
    }

    // RFC 8484 DoH Endpoint
    if (url.pathname === '/dns-query') {
      // 1. Authenticate Device Bearer Token
      const authHeader = req.headers['authorization'];
      const authResult = this.authenticator.authenticateHeader(authHeader);

      if (!authResult.authenticated || !authResult.context) {
        res.writeHead(authResult.errorStatus ?? 401, {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer error="invalid_token"',
        });
        res.end(JSON.stringify({ error: authResult.errorMessage }));
        return;
      }

      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress;

      // 2. Handle POST application/dns-message
      if (req.method === 'POST') {
        const contentType = req.headers['content-type'];
        if (contentType !== 'application/dns-message') {
          res.writeHead(415, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unsupported Media Type: Expected application/dns-message' }));
          return;
        }

        const chunks: Buffer[] = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', async () => {
          const bodyBuffer = Buffer.concat(chunks);
          const result = await this.handler.handleDnsMessage(bodyBuffer, authResult.context!, clientIp);

          if (result.statusCode !== 200 || !result.responseBuffer) {
            res.writeHead(result.statusCode, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: result.errorMessage }));
            return;
          }

          res.writeHead(200, {
            'Content-Type': 'application/dns-message',
            'Content-Length': result.responseBuffer.length,
            'X-Policy-Action': result.action,
            'X-Resolution-Microseconds': Math.round(result.latencyMicroseconds),
          });
          res.end(result.responseBuffer);
        });
        return;
      }

      // 3. Handle GET application/dns-message with ?dns=base64url
      if (req.method === 'GET') {
        const dnsParam = url.searchParams.get('dns');
        if (!dnsParam) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing dns query parameter' }));
          return;
        }

        const bodyBuffer = Buffer.from(dnsParam, 'base64url');
        const result = await this.handler.handleDnsMessage(bodyBuffer, authResult.context!, clientIp);

        if (result.statusCode !== 200 || !result.responseBuffer) {
          res.writeHead(result.statusCode, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: result.errorMessage }));
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'application/dns-message',
          'Content-Length': result.responseBuffer.length,
          'X-Policy-Action': result.action,
          'X-Resolution-Microseconds': Math.round(result.latencyMicroseconds),
        });
        res.end(result.responseBuffer);
        return;
      }

      res.writeHead(405, { 'Content-Type': 'application/json', Allow: 'POST, GET' });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  }
}
