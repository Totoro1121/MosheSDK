import { describe, expect, it } from 'vitest';

import {
  domainMatchesPattern,
  isLocalNetworkHost,
  matchesOutboundPattern,
  parseOutboundTarget
} from '../src/outbound-utils.js';

describe('parseOutboundTarget', () => {
  it('parses a standard HTTPS URL correctly', () => {
    const result = parseOutboundTarget('https://api.example.com/v1/data');
    expect(result).toEqual({
      scheme: 'https',
      hostname: 'api.example.com',
      port: '',
      pathname: '/v1/data'
    });
  });

  it('parses URL with port', () => {
    const result = parseOutboundTarget('https://api.example.com:8443/health');
    expect(result?.hostname).toBe('api.example.com');
    expect(result?.port).toBe('8443');
  });

  it('returns null for non-URL string', () => {
    expect(parseOutboundTarget('not-a-url')).toBeNull();
  });

  it('lowercases hostname', () => {
    expect(parseOutboundTarget('HTTPS://API.EXAMPLE.COM/path')?.hostname).toBe('api.example.com');
  });
});

describe('domainMatchesPattern', () => {
  it('exact match returns true', () => {
    expect(domainMatchesPattern('api.example.com', 'api.example.com')).toBe(true);
  });

  it('subdomain matches parent domain', () => {
    expect(domainMatchesPattern('api.example.com', 'example.com')).toBe(true);
  });

  it('deep subdomain matches ancestor domain', () => {
    expect(domainMatchesPattern('v2.api.example.com', 'example.com')).toBe(true);
  });

  it('different domain with shared suffix does not match', () => {
    expect(domainMatchesPattern('notexample.com', 'example.com')).toBe(false);
  });

  it('evil prefix does not match', () => {
    expect(domainMatchesPattern('evil-example.com', 'example.com')).toBe(false);
  });

  it('wildcard matches direct subdomain', () => {
    expect(domainMatchesPattern('api.example.com', '*.example.com')).toBe(true);
  });

  it('wildcard does not match root domain', () => {
    expect(domainMatchesPattern('example.com', '*.example.com')).toBe(true);
  });

  it('wildcard does not match sibling suffix', () => {
    expect(domainMatchesPattern('notexample.com', '*.example.com')).toBe(false);
  });
});

describe('matchesOutboundPattern', () => {
  it('full URL matches domain-only pattern', () => {
    expect(matchesOutboundPattern('https://api.example.com/query', 'example.com')).toBe(true);
  });

  it('URL matches subdomain of blocked domain', () => {
    expect(matchesOutboundPattern('https://evil.malware.com/x', 'malware.com')).toBe(true);
  });

  it('URL does not match unrelated domain with shared suffix', () => {
    expect(matchesOutboundPattern('https://notexample.com/path', 'example.com')).toBe(false);
  });

  it('path prefix match', () => {
    expect(matchesOutboundPattern('https://api.example.com/v1/users', 'api.example.com/v1')).toBe(true);
  });

  it('path prefix mismatch', () => {
    expect(matchesOutboundPattern('https://api.example.com/v2/users', 'api.example.com/v1')).toBe(false);
  });

  it('scheme enforcement: https does not match http pattern', () => {
    expect(matchesOutboundPattern('https://api.example.com', 'http://api.example.com')).toBe(false);
  });

  it('scheme-agnostic pattern matches both schemes', () => {
    expect(matchesOutboundPattern('https://api.example.com', 'api.example.com')).toBe(true);
    expect(matchesOutboundPattern('http://api.example.com', 'api.example.com')).toBe(true);
  });

  it('URL with port still matches hostname pattern', () => {
    expect(matchesOutboundPattern('https://api.example.com:8443/data', 'example.com')).toBe(true);
  });

  it('wildcard pattern matches subdomains but not root domain', () => {
    expect(matchesOutboundPattern('https://api.example.com/data', '*.example.com')).toBe(true);
    expect(matchesOutboundPattern('https://example.com/data', '*.example.com')).toBe(true);
  });

  it('explicit port in pattern must match target port', () => {
    expect(matchesOutboundPattern('https://evil.com:443/data', 'evil.com:443')).toBe(true);
    expect(matchesOutboundPattern('https://evil.com:80/data', 'evil.com:443')).toBe(false);
  });

  it('falls back to substring for unparseable targets', () => {
    expect(matchesOutboundPattern('example.com/raw-target', 'example.com')).toBe(true);
  });
});

describe('isLocalNetworkHost', () => {
  it('localhost returns true', () => {
    expect(isLocalNetworkHost('localhost')).toBe(true);
  });

  it('0.0.0.0 returns true', () => {
    expect(isLocalNetworkHost('0.0.0.0')).toBe(true);
  });

  it('::1 returns true', () => {
    expect(isLocalNetworkHost('::1')).toBe(true);
  });

  it('real domain returns false', () => {
    expect(isLocalNetworkHost('api.example.com')).toBe(false);
  });

  it('domain containing localhost string is not local', () => {
    expect(isLocalNetworkHost('localhost.example.com')).toBe(false);
  });

  it('127.x loopback range returns true', () => {
    expect(isLocalNetworkHost('127.0.0.1')).toBe(true);
    expect(isLocalNetworkHost('127.1.2.3')).toBe(true);
  });
});
