export interface ParsedTarget {
  scheme: string;
  hostname: string;
  port: string;
  pathname: string;
}

interface ParsedPattern extends ParsedTarget {
  wildcard: boolean;
}

export function parseOutboundTarget(target: string): ParsedTarget | null {
  try {
    const url = new URL(target);
    return {
      scheme: url.protocol.replace(':', ''),
      hostname: url.hostname.toLowerCase(),
      port: url.port,
      pathname: url.pathname || '/'
    };
  } catch {
    return null;
  }
}

export function domainMatchesPattern(hostname: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    return hostname.endsWith(`.${suffix}`);
  }

  return hostname === pattern || hostname.endsWith(`.${pattern}`);
}

export function isLocalNetworkHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === 'localhost'
    || h === '0.0.0.0'
    || h === '::1'
    || h === '[::1]';
}

function parsePatternTarget(pattern: string): ParsedPattern | null {
  const schemeMatch = pattern.match(/^(https?):\/\//);
  const scheme = schemeMatch?.[1] ?? 'https';
  const remainder = schemeMatch ? pattern.slice(schemeMatch[0].length) : pattern;
  const slashIndex = remainder.indexOf('/');
  const authority = slashIndex >= 0 ? remainder.slice(0, slashIndex) : remainder;
  const path = slashIndex >= 0 ? remainder.slice(slashIndex) : '/';

  if (authority.trim() === '') {
    return null;
  }

  const withoutAuth = authority.replace(/^\*\./, 'wildcard-placeholder.');
  const parsed = parseOutboundTarget(`${scheme}://${withoutAuth}${path}`);
  if (!parsed) {
    return null;
  }

  const wildcard = authority.startsWith('*.');
  const portIndex = authority.lastIndexOf(':');
  const hasPort = portIndex > -1 && !authority.includes(']');
  const hostname = (hasPort ? authority.slice(0, portIndex) : authority).toLowerCase();

  return {
    scheme: parsed.scheme,
    hostname,
    port: hasPort ? authority.slice(portIndex + 1) : parsed.port,
    pathname: parsed.pathname,
    wildcard
  };
}

export function matchesOutboundPattern(target: string, pattern: string): boolean {
  const normalizedPattern = pattern.trim().toLowerCase();
  const parsedTarget = parseOutboundTarget(target);

  if (!parsedTarget) {
    return target.toLowerCase().includes(normalizedPattern);
  }

  const patternHasScheme = normalizedPattern.startsWith('http://') || normalizedPattern.startsWith('https://');
  const parsedPattern = parsePatternTarget(normalizedPattern);

  if (!parsedPattern) {
    return target.toLowerCase().includes(normalizedPattern);
  }

  if (patternHasScheme && parsedTarget.scheme !== parsedPattern.scheme) {
    return false;
  }

  if (!domainMatchesPattern(parsedTarget.hostname, parsedPattern.hostname)) {
    return false;
  }

  if (parsedPattern.pathname && parsedPattern.pathname !== '/') {
    if (!parsedTarget.pathname.startsWith(parsedPattern.pathname)) {
      return false;
    }
  }

  return true;
}
