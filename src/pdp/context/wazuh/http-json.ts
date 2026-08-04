import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { URL } from 'node:url';

/**
 * Minimal, dependency-free JSON HTTP client. Node's global fetch (undici) does
 * not expose a per-request TLS-verify toggle without importing undici, and Wazuh
 * serves HTTPS with a self-signed cert by default — so we use node:https, which
 * accepts `rejectUnauthorized` on the request options directly.
 */
export interface HttpJsonOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
  /** false => accept self-signed certs (Wazuh default). */
  rejectUnauthorized: boolean;
}

export interface HttpJsonResult {
  status: number;
  json: unknown;
}

export function httpJson(
  url: string,
  opts: HttpJsonOptions,
): Promise<HttpJsonResult> {
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const doRequest = isHttps ? httpsRequest : httpRequest;

  return new Promise<HttpJsonResult>((resolve, reject) => {
    const req = doRequest(
      {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method: opts.method ?? 'GET',
        headers: opts.headers,
        ...(isHttps ? { rejectUnauthorized: opts.rejectUnauthorized } : {}),
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let json: unknown;
          try {
            json = data ? JSON.parse(data) : undefined;
          } catch {
            json = data;
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );

    req.on('error', reject);
    req.setTimeout(opts.timeoutMs, () => {
      req.destroy(new Error(`request timed out after ${opts.timeoutMs}ms`));
    });

    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}
