const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const hashNames = {SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512"};

function decodeBase32(secret) {
  const bytes = [];
  let buffer = 0;
  let length = 0;
  for (const character of secret) {
    const value = base32.indexOf(character);
    if (value < 0) {
      throw new Error("Enter a Base32 TOTP secret.");
    }
    buffer = (buffer << 5) | value;
    length += 5;
    if (length >= 8) {
      length -= 8;
      bytes.push((buffer >> length) & 0xff);
    }
  }
  if (bytes.length === 0) {
    throw new Error("The TOTP secret is missing.");
  }
  return Uint8Array.from(bytes);
}

export function parseTotp(input) {
  const text = String(input).trim();
  let fields = new URLSearchParams({secret: text});
  let label = "";
  if (text.toLowerCase().startsWith("otpauth:")) {
    const uri = new URL(text);
    if (uri.protocol !== "otpauth:" || uri.hostname !== "totp" || uri.username || uri.password) {
      throw new Error("Use a QR code for time-based one-time passwords.");
    }
    fields = uri.searchParams;
    label = decodeURIComponent(uri.pathname.slice(1)).split(":").at(-1).trim();
  }
  const secret = (fields.get("secret") ?? "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  const algorithm = (fields.get("algorithm") ?? "SHA1").toUpperCase().replaceAll("-", "");
  const digits = Number(fields.get("digits") ?? 6);
  const period = Number(fields.get("period") ?? 30);
  if (secret.length > 1024 || !Object.hasOwn(hashNames, algorithm) || ![6, 8].includes(digits) ||
      !Number.isInteger(period) || period < 1 || period > 3600) {
    throw new Error("The TOTP format or settings are unsupported.");
  }
  decodeBase32(secret);
  return {secret, algorithm, digits, period, label};
}

export function formatTotp({secret, algorithm, digits, period, label}) {
  if (!label && algorithm === "SHA1" && digits === 6 && period === 30) return secret;
  // Keep dot-only account labels from being normalized away as URL path segments.
  const path = label === "." || label === ".." ? label + "%20" : encodeURIComponent(label);
  const parameters = new URLSearchParams({secret, algorithm, digits, period});
  return `otpauth://totp/${path}?${parameters}`;
}

export async function totpSnapshot({secret, algorithm, digits, period}, now = Date.now()) {
  const interval = period * 1000;
  const counter = Math.floor(now / interval);
  const message = new DataView(new ArrayBuffer(8));
  message.setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey(
    "raw", decodeBase32(secret), {name: "HMAC", hash: hashNames[algorithm]}, false, ["sign"],
  );
  const digest = new DataView(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest.getUint8(digest.byteLength - 1) & 15;
  const value = digest.getUint32(offset) & 0x7fffffff;
  return {
    code: String(value % (10 ** digits)).padStart(digits, "0"),
    expiresAt: (counter + 1) * interval,
  };
}

export async function currentTotp(record, now) {
  return (await totpSnapshot(record, now)).code;
}
