(() => {
  "use strict";
  const container = navigator.credentials;
  if (!container || !window.isSecureContext) return;

  const channel = "bigmouth/webauthn";
  const origin = location.origin;
  const pending = new Map();

  function send(detail) {
    window.postMessage({channel, direction: "from-page", ...detail}, origin);
  }

  window.addEventListener("message", ({source, origin: from, data}) => {
    if (source !== window || from !== origin || data?.channel !== channel || data.direction !== "from-extension") {
      return;
    }
    const request = pending.get(data.id);
    if (!request) return;
    clearTimeout(request.ackTimeout);
    if (!data.ack) request.resolve(data);
  });

  function ask(detail, signal, timeout) {
    return new Promise((resolve, reject) => {
      const id = crypto.randomUUID();
      const clear = () => {
        clearTimeout(ackTimeout);
        clearTimeout(deadline);
        signal?.removeEventListener("abort", abort);
        pending.delete(id);
      };
      const abort = () => {
        clear();
        send({id, cancel: true});
        reject(signal.reason);
      };
      if (signal?.aborted) {
        reject(signal.reason);
        return;
      }
      const ackTimeout = setTimeout(() => {
        clear();
        resolve({value: {fallback: true}});
      }, 500);
      const deadline = setTimeout(() => {
        clear();
        send({id, cancel: true});
        reject(new DOMException("WebAuthn operation timed out.", "NotAllowedError"));
      }, timeout);
      pending.set(id, {
        ackTimeout,
        resolve: (data) => {
          clear();
          if (data.error) {
            reject(data.name === "TypeError" ? new TypeError(data.error) : new DOMException(data.error, data.name));
          } else {
            resolve(data);
          }
        },
      });
      signal?.addEventListener("abort", abort, {once: true});
      send({id, ...detail});
    });
  }

  function base64(buffer) {
    const bytes = ArrayBuffer.isView(buffer)
      ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
      : new Uint8Array(buffer);
    return bytes.toBase64({alphabet: "base64url", omitPadding: true});
  }

  function bytes(value) {
    return Uint8Array.fromBase64(value, {alphabet: "base64url"}).buffer;
  }

  function encodeOptions(value) {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return base64(value);
    if (Array.isArray(value)) return value.map(encodeOptions);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeOptions(item)]));
    }
    return value;
  }

  function makeCredential(json, method) {
    const data = json.response;
    const rawId = bytes(json.rawId);
    const clientDataJSON = bytes(data.clientDataJSON);
    const authenticatorData = bytes(data.authenticatorData);
    const response = method === "create"
      ? Object.create(AuthenticatorAttestationResponse.prototype, {
        clientDataJSON: {value: clientDataJSON},
        attestationObject: {value: bytes(data.attestationObject)},
        getAuthenticatorData: {value: () => authenticatorData},
        getPublicKey: {value: () => bytes(data.publicKey)},
        getPublicKeyAlgorithm: {value: () => data.publicKeyAlgorithm},
        getTransports: {value: () => [...data.transports]},
      })
      : Object.create(AuthenticatorAssertionResponse.prototype, {
        clientDataJSON: {value: clientDataJSON},
        authenticatorData: {value: authenticatorData},
        signature: {value: bytes(data.signature)},
        userHandle: {value: data.userHandle ? bytes(data.userHandle) : null},
      });
    return Object.create(PublicKeyCredential.prototype, {
      id: {value: json.id},
      rawId: {value: rawId},
      type: {value: json.type},
      authenticatorAttachment: {value: json.authenticatorAttachment},
      response: {value: response},
      getClientExtensionResults: {value: () => structuredClone(json.clientExtensionResults)},
      toJSON: {value: () => structuredClone(json)},
    });
  }

  function patch(target, property, replace) {
    const descriptor = Object.getOwnPropertyDescriptor(target, property);
    if (typeof target[property] !== "function" || (descriptor && !descriptor.configurable)) return;
    const original = target[property];
    Object.defineProperty(target, property, {value: replace(original), configurable: true, writable: true});
  }

  for (const method of ["create", "get"]) {
    patch(container, method, (original) => async function (options) {
      if (this !== container || !options?.publicKey || options.mediation === "silent" ||
          (method === "create" && options.mediation === "conditional")) {
        return original.call(this, options);
      }
      const data = await ask({
        method,
        mediation: options.mediation,
        options: encodeOptions(options.publicKey),
      }, options.signal, options.mediation === "conditional" ? 300_000 :
        Math.min(120_000, Math.max(1_000, Number(options.publicKey.timeout) || 90_000)));
      return data.value?.fallback ? original.call(this, options) : makeCredential(data.value, method);
    });
  }

  for (const property of ["isUserVerifyingPlatformAuthenticatorAvailable", "isConditionalMediationAvailable"]) {
    patch(PublicKeyCredential, property, (original) => async function () {
      return (await ask({capability: true}, null, 2_000)).value === true || original.call(this);
    });
  }
  patch(PublicKeyCredential, "getClientCapabilities", (original) => async function () {
    const capabilities = await original.call(this);
    if ((await ask({capability: true}, null, 2_000)).value === true) {
      return {...capabilities, passkeyPlatformAuthenticator: true, conditionalGet: true,
        userVerifyingPlatformAuthenticator: true};
    }
    return capabilities;
  });
})();
