const es256 = -7;
const keyAlgorithm = {name: "ECDSA", namedCurve: "P-256"};
// Public P-256 fixture key with private scalar 1. Never use with real accounts.
const testKey = {
  crv: "P-256",
  kty: "EC",
  x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
  y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
  d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
  kid: "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
};
const testAaguid = Uint8Array.of(
  0x32, 0x4b, 0x85, 0xf4, 0xd4, 0x90, 0x40, 0x1d,
  0x91, 0x56, 0xd8, 0x15, 0x02, 0x09, 0x05, 0xab,
);
const encoder = new TextEncoder();

function toBase64Url(bytes) {
  return bytes.toBase64({alphabet: "base64url", omitPadding: true});
}

export function fromBase64Url(value) {
  return Uint8Array.fromBase64(value, {alphabet: "base64url"});
}

function joinBytes(...parts) {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function cborHeader(type, value) {
  const prefix = type << 5;
  if (value < 24) {
    return Uint8Array.of(prefix | value);
  }
  if (value <= 0xff) {
    return Uint8Array.of(prefix | 24, value);
  }
  return Uint8Array.of(prefix | 25, value >> 8, value & 0xff);
}

// These are the CBOR types used by the COSE key and the attestation object.
function encodeCbor(value) {
  if (Number.isInteger(value)) {
    return value >= 0 ? cborHeader(0, value) : cborHeader(1, -1 - value);
  }
  if (value instanceof Uint8Array) {
    return joinBytes(cborHeader(2, value.length), value);
  }
  if (typeof value === "string") {
    const bytes = encoder.encode(value);
    return joinBytes(cborHeader(3, bytes.length), bytes);
  }
  return joinBytes(
    cborHeader(5, value.size),
    ...Array.from(value, ([key, item]) => joinBytes(encodeCbor(key), encodeCbor(item))),
  );
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function authenticatorData(rpId, verified, attestedData) {
  const flags = 0x01 | (verified ? 0x04 : 0) | (attestedData ? 0x40 : 0);
  const header = joinBytes(await sha256(encoder.encode(rpId)), Uint8Array.of(flags, 0, 0, 0, 0));
  return attestedData ? joinBytes(header, attestedData) : header;
}

function clientData(type, challenge, origin) {
  return encoder.encode(JSON.stringify({type, challenge, origin, crossOrigin: false}));
}

function asDerInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }
  const value = bytes.subarray(start);
  if (value[0] & 0x80) {
    return joinBytes(Uint8Array.of(0x02, value.length + 1, 0), value);
  }
  return joinBytes(Uint8Array.of(0x02, value.length), value);
}

function signatureToDer(signature) {
  const r = asDerInteger(signature.subarray(0, 32));
  const s = asDerInteger(signature.subarray(32));
  return joinBytes(Uint8Array.of(0x30, r.length + s.length), r, s);
}

function credentialResponse(id, response, clientExtensionResults = {}) {
  return {
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    clientExtensionResults,
  };
}

export function signablePasskeys({passkeys}) {
  return passkeys.filter(({keyId}) => keyId === testKey.kid);
}

export function registrationRecord(options) {
  const handle = fromBase64Url(options.user.id);
  if (handle.length === 0 || handle.length > 64) {
    throw new DOMException("The user handle must be 1 to 64 bytes.", "TypeError");
  }

  return {
    id: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    rpId: options.rp.id,
    userHandle: options.user.id,
    keyId: testKey.kid,
  };
}

export async function createResponse(options, origin, record, verified) {
  const {kty, crv, x, y} = testKey;
  const publicKey = await crypto.subtle.importKey("jwk", {kty, crv, x, y}, keyAlgorithm, true, ["verify"]);
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  const coseKey = encodeCbor(new Map([
    [1, 2], [3, es256], [-1, 1], [-2, fromBase64Url(x)], [-3, fromBase64Url(y)],
  ]));
  const idBytes = fromBase64Url(record.id);
  const attestedData = joinBytes(testAaguid, Uint8Array.of(0, idBytes.length), idBytes, coseKey);
  const data = await authenticatorData(record.rpId, verified, attestedData);
  const attestationObject = encodeCbor(new Map([
    ["fmt", "none"],
    ["attStmt", new Map()],
    ["authData", data],
  ]));

  return credentialResponse(record.id, {
    clientDataJSON: toBase64Url(clientData("webauthn.create", options.challenge, origin)),
    authenticatorData: toBase64Url(data),
    publicKey: toBase64Url(publicKeyBytes),
    publicKeyAlgorithm: es256,
    transports: ["internal"],
    attestationObject: toBase64Url(attestationObject),
  }, options.extensions?.credProps ? {credProps: {rk: true}} : {});
}

export async function getResponse(options, origin, record, verified) {
  const data = await authenticatorData(record.rpId, verified);
  const client = clientData("webauthn.get", options.challenge, origin);
  const signedData = joinBytes(data, await sha256(client));
  const key = await crypto.subtle.importKey("jwk", testKey, keyAlgorithm, false, ["sign"]);
  const rawSignature = new Uint8Array(await crypto.subtle.sign(
    {name: "ECDSA", hash: "SHA-256"}, key, signedData,
  ));
  return credentialResponse(record.id, {
    clientDataJSON: toBase64Url(client),
    authenticatorData: toBase64Url(data),
    signature: toBase64Url(signatureToDer(rawSignature)),
    userHandle: record.userHandle,
  });
}
