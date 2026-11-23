export const defaultOrigins = [];

function parseOriginPattern(pattern) {
  const parts = /^(https?):\/\/(\*\.)?(\[[a-f0-9:.]+\]|[^:/?#@*\\\s]+)(?::(\d+|\*))?\/?$/i.exec(pattern);
  if (!parts) {
    throw new Error("Enter a valid origin.");
  }

  const [, scheme, wildcard, host, port] = parts;
  const url = new URL(scheme + "://" + host + (port && port !== "*" ? ":" + port : ""));
  if (url.hostname.includes("*")) {
    throw new Error("Enter a valid origin.");
  }
  const isLoopback = url.hostname === "localhost" || url.hostname.endsWith(".localhost") ||
    url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol === "http:" && !isLoopback) {
    throw new Error("HTTP is supported only for loopback test origins.");
  }
  if (wildcard && (url.hostname.startsWith("[") || /^[\d.]+$/.test(url.hostname))) {
    throw new Error("Use host wildcards with domain names.");
  }

  return {url, wildcard: Boolean(wildcard), anyPort: port === "*"};
}

export function normalizeOrigin(input) {
  const {url, wildcard, anyPort} = parseOriginPattern(input.trim());
  if (wildcard || anyPort) throw new Error("Enter an exact origin.");
  return url.origin;
}

export function normalizeOrigins(input) {
  const patterns = input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  return [...new Set(patterns.map((pattern) => {
    const {url, wildcard, anyPort} = parseOriginPattern(pattern);
    return url.protocol + "//" + (wildcard ? "*." : "") + url.host + (anyPort ? ":*" : "");
  }))];
}

export function injectionMatches(patterns) {
  return [...new Set(patterns.map((pattern) => {
    const {url, wildcard, anyPort} = parseOriginPattern(pattern);
    const port = anyPort ? "" : ":" + (url.port || (url.protocol === "https:" ? "443" : "80"));
    return url.protocol + "//" + (wildcard ? "*." : "") + url.hostname + port + "/*";
  }))];
}

export function matchesOrigin(origin, patterns) {
  const candidate = new URL(origin);
  return patterns.some((pattern) => {
    const {url, wildcard, anyPort} = parseOriginPattern(pattern);
    const matchesHost = wildcard
      ? candidate.hostname.endsWith("." + url.hostname)
      : candidate.hostname === url.hostname;
    return matchesHost && candidate.protocol === url.protocol && (anyPort || candidate.port === url.port);
  });
}
