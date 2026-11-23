const form = document.querySelector("#passkey");
const username = form.elements.username;
const register = document.querySelector("#passkey-register");
const login = document.querySelector("#passkey-login");
const result = document.querySelector("#passkey-result");
const keyPrefix = "passkey-test:";
const rpId = location.hostname;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let conditional;
let busy = false;

function base64(bytes) {
  return new Uint8Array(bytes).toBase64();
}

function verifyClientData(response, type, challenge) {
  const client = JSON.parse(decoder.decode(response.clientDataJSON));
  const expected = challenge.toBase64({alphabet: "base64url", omitPadding: true});
  if (client.type !== type || client.origin !== location.origin || client.challenge !== expected) {
    throw new Error("The operation type, origin, or challenge did not match.");
  }
}

function rawSignature(buffer) {
  // WebAuthn returns DER, while Web Crypto verifies the fixed-width r and s values.
  const der = new Uint8Array(buffer);
  const raw = new Uint8Array(64);
  let cursor = 2;
  const invalid = () => new Error("Invalid ES256 signature format.");
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw invalid();
  for (const start of [0, 32]) {
    if (der[cursor++] !== 0x02) throw invalid();
    const length = der[cursor++];
    if (!length || length > 33 || cursor + length > der.length || (der[cursor] & 0x80)) throw invalid();
    const skip = der[cursor] === 0 ? 1 : 0;
    const integer = der.subarray(cursor + skip, cursor + length);
    if (integer.length > 32) throw invalid();
    raw.set(integer, start + 32 - integer.length);
    cursor += length;
  }
  if (cursor !== der.length) throw invalid();
  return raw;
}

async function registerPasskey() {
  const name = username.value.trim();
  if (!name) throw new Error("Enter a username.");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({publicKey: {
    challenge,
    rp: {id: rpId, name: "Password Manager for Test"},
    user: {id: await crypto.subtle.digest("SHA-256", encoder.encode(name)), name, displayName: name},
    pubKeyCredParams: [{type: "public-key", alg: -7}],
    authenticatorSelection: {residentKey: "required", userVerification: "preferred"},
    attestation: "none",
  }});
  if (!credential) throw new Error("Could not register the passkey.");
  verifyClientData(credential.response, "webauthn.create", challenge);
  const publicKey = credential.response.getPublicKey();
  if (!publicKey) throw new Error("Could not retrieve the public key.");
  localStorage.setItem(keyPrefix + credential.id, base64(publicKey));
  result.textContent = "Passkey registered.";
}

async function authenticate(mediation, signal) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.get({mediation, signal, publicKey: {
    challenge, rpId, userVerification: "preferred",
  }});
  const savedKey = localStorage.getItem(keyPrefix + credential?.id);
  if (!savedKey) throw new Error("Select a passkey registered on this page.");
  const response = credential.response;
  verifyClientData(response, "webauthn.get", challenge);
  const authData = new Uint8Array(response.authenticatorData);
  const rpHash = await crypto.subtle.digest("SHA-256", encoder.encode(rpId));
  if (authData.length < 37 || !(authData[32] & 1) || base64(authData.subarray(0, 32)) !== base64(rpHash)) {
    throw new Error("The RP ID hash or user presence flag did not match.");
  }
  const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", response.clientDataJSON));
  const signed = new Uint8Array(authData.length + clientHash.length);
  signed.set(authData);
  signed.set(clientHash, authData.length);
  const publicKey = await crypto.subtle.importKey("spki", Uint8Array.fromBase64(savedKey),
    {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
  if (!await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, publicKey, rawSignature(response.signature), signed)) {
    throw new Error("Could not verify the signature.");
  }
  if (!signal?.aborted) {
    const method = mediation === "conditional" ? "Conditional UI" : "the button";
    result.textContent = `Signed in via ${method}. Signature verified.`;
  }
}

async function startConditional() {
  if (busy || conditional || !Object.keys(localStorage).some((key) => key.startsWith(keyPrefix))) return;
  const controller = new AbortController();
  conditional = controller;
  try {
    await authenticate("conditional", controller.signal);
  } catch (error) {
    if (!controller.signal.aborted) result.textContent = `Conditional UI error. ${error.message || error.name}`;
  } finally {
    if (conditional === controller) conditional = null;
  }
}

async function runButton(operation) {
  conditional?.abort();
  conditional = null;
  busy = register.disabled = login.disabled = true;
  result.textContent = "Waiting for passkey confirmation...";
  try {
    await operation();
  } catch (error) {
    result.textContent = error.message || error.name;
  } finally {
    busy = register.disabled = login.disabled = false;
    void startConditional();
  }
}

register.addEventListener("click", () => { void runButton(registerPasskey); });
form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!busy) void runButton(() => authenticate("required"));
});
username.addEventListener("focus", startConditional);
username.addEventListener("click", startConditional);
void startConditional();
