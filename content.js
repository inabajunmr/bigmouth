(() => {
  "use strict";
  const channel = "bigmouth/webauthn";
  const generated = new WeakMap();
  const submitted = new WeakMap();
  const pendingPasskeys = new Map();
  const bridgeRequests = new Map();
  const scannedImages = new WeakMap();
  const seenCodes = new Set();
  const popupStyle = new CSSStyleSheet();
  popupStyle.replaceSync(
    ":host{all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;color-scheme:light dark}" +
    "section{display:grid;gap:5px;box-sizing:border-box;padding:8px;border:1px solid GrayText;" +
    "min-width:min(220px,calc(100vw - 24px));max-width:min(360px,calc(100vw - 24px));" +
    "max-height:65vh;overflow:auto;" +
    "border-radius:8px;background:Canvas;color:CanvasText;font:13px/1.5 system-ui,sans-serif;" +
    "box-shadow:0 8px 30px #0003}" +
    "form{display:grid;gap:5px}input,select{box-sizing:border-box;width:100%;font:inherit;margin-top:4px}" +
    ".check{display:flex;align-items:center;gap:6px}.check input{width:auto;margin:0}" +
    "button{padding:7px 9px;text-align:left;font:inherit;color:inherit;background:ButtonFace;" +
    "border:1px solid GrayText;border-radius:5px;cursor:pointer;overflow-wrap:anywhere}" +
    "button:hover{background:Highlight;color:HighlightText}p{margin:0;padding:2px 4px}",
  );
  let suggestion;
  let suggestionField;
  let notice;
  let passkeyPrompt;
  let scanning = false;
  let focusGeneration = 0;

  async function send(action, detail = {}) {
    const response = await chrome.runtime.sendMessage({action, ...detail});
    if (response?.error) throw new DOMException(response.error, response.name ?? "Error");
    return response?.value;
  }

  function makePopup() {
    const host = document.createElement("div");
    const root = host.attachShadow({mode: "closed"});
    root.adoptedStyleSheets = [popupStyle];
    const section = root.appendChild(document.createElement("section"));
    section.lang = "en";
    section.setAttribute("aria-label", "bigmouth");
    (document.body ?? document.documentElement).append(host);
    return {host, section};
  }

  function addButton(widget, label, action) {
    const button = widget.section.appendChild(document.createElement("button"));
    button.type = "button";
    button.textContent = label;
    button.addEventListener("pointerdown", (event) => event.preventDefault());
    button.addEventListener("click", (event) => {
      if (!event.isTrusted) return;
      button.disabled = true;
      Promise.resolve().then(action).catch((error) => showNotice(error.message)).finally(() => {
        button.disabled = false;
      });
    });
    return button;
  }

  function removeSuggestion() {
    focusGeneration++;
    suggestion?.host.remove();
    suggestion = null;
    suggestionField = null;
    updateNoticeVisibility();
  }

  function updateNoticeVisibility() {
    if (notice) notice.host.style.display = passkeyPrompt || suggestion ? "none" : "";
  }

  function showNotice(message, actionLabel, action) {
    notice?.host.remove();
    notice = makePopup();
    updateNoticeVisibility();
    const text = notice.section.appendChild(document.createElement("p"));
    text.setAttribute("role", "status");
    text.textContent = message;
    if (actionLabel) addButton(notice, actionLabel, action);
    addButton(notice, "Close", () => notice?.host.remove());
    return notice;
  }

  function fill(field, value) {
    if (!field?.isConnected || field.readOnly || field.disabled) return;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(field, value);
    field.dispatchEvent(new Event("input", {bubbles: true}));
    field.dispatchEvent(new Event("change", {bubbles: true}));
  }

  function fieldScope(field) {
    return field.form ?? field.closest('[role="form"]') ?? document;
  }

  function fieldHint(field) {
    return [field.name, field.id, field.placeholder, ...Array.from(field.labels ?? [], (label) => label.textContent)]
      .join(" ").toLowerCase();
  }

  function tokens(field) {
    return field.autocomplete.toLowerCase().split(/\s+/);
  }

  // Unicode escapes preserve matching for Japanese form labels and buttons.
  function newFields(scope) {
    const fields = [...scope.querySelectorAll('input[type="password"]:not([disabled]):not([readonly])')];
    const possible = fields.filter((field) => !tokens(field).includes("current-password") &&
      !/current.?password|old.?password|\u73fe\u5728\u306e\u30d1\u30b9\u30ef\u30fc\u30c9/.test(fieldHint(field)));
    const explicit = possible.filter((field) => tokens(field).includes("new-password") ||
      /new.?password|password.?confirm|confirm.?password|repeat.?password|retype|\u65b0\u3057\u3044\u30d1\u30b9\u30ef\u30fc\u30c9|\u30d1\u30b9\u30ef\u30fc\u30c9.*\u78ba\u8a8d/.test(fieldHint(field)));
    if (explicit.length === 1 && possible.length === 2 &&
        /confirm|repeat|retype|\u78ba\u8a8d/.test(fieldHint(explicit[0]))) return possible;
    if (explicit.length) return explicit;
    if (scope === document) return [];
    const hints = [
      scope.getAttribute("action"), scope.id, scope.getAttribute("name"),
      ...Array.from(scope.querySelectorAll('button[type="submit"],input[type="submit"],button:not([type])'),
        (button) => button.value || button.textContent),
    ].join(" ");
    return /sign.?up|register|create.?account|\u65b0\u898f\u767b\u9332|\u767b\u9332\u3059\u308b/.test(hints.toLowerCase()) ? possible : [];
  }

  function usernameField(scope) {
    const fields = [...scope.querySelectorAll('input:not([disabled])')];
    return fields.find((field) => tokens(field).includes("username")) ??
      fields.find((field) => field.type === "email" || tokens(field).includes("email")) ??
      fields.find((field) => field.type === "text" && /user|login|email|\u540d\u524d|\u30e1\u30fc\u30eb/.test(fieldHint(field)));
  }

  function randomChoice(length) {
    const limit = 256 - (256 % length);
    let value;
    do { value = crypto.getRandomValues(new Uint8Array(1))[0]; } while (value >= limit);
    return value % length;
  }

  function generatePassword(fields) {
    const groups = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!#$%&*-_"];
    const pool = groups.join("");
    const length = Math.min(20, ...fields.map(({maxLength}) => maxLength < 0 ? 20 : maxLength));
    if (length < groups.length) throw new Error("This field is too short for a generated password.");
    const characters = groups.map((group) => group[randomChoice(group.length)]);
    while (characters.length < length) characters.push(pool[randomChoice(pool.length)]);
    for (let index = characters.length - 1; index > 0; index--) {
      const other = randomChoice(index + 1);
      [characters[index], characters[other]] = [characters[other], characters[index]];
    }
    return characters.join("");
  }

  function isOtp(field) {
    return tokens(field).includes("one-time-code") || /(^|[\s_-])(totp|otp|verification.code|\u78ba\u8a8d\u30b3\u30fc\u30c9)([\s_-]|$)/.test(fieldHint(field));
  }

  async function suggest(field) {
    removeSuggestion();
    if (passkeyPrompt || !(field instanceof HTMLInputElement) || field.readOnly || field.disabled) return;
    const scope = fieldScope(field);
    const username = usernameField(scope);
    const usernameFocused = field === username || field.type === "email" || tokens(field).includes("email");
    const newPasswords = newFields(scope);
    const passwordField = field.type === "password" ? field :
      usernameFocused ? newPasswords[0] ?? scope.querySelector('input[type="password"]:not([disabled]):not([readonly])') : null;
    const otp = isOtp(field);
    const conditional = tokens(field).includes("webauthn") ? pendingPasskeys.values().next().value : null;
    if (!passwordField && !usernameFocused && !otp && !conditional) return;

    const generation = focusGeneration;
    suggestionField = field;
    const accounts = await send("site-accounts").catch(() => null);
    if (generation !== focusGeneration) return;
    if (!accounts || document.activeElement !== field) return removeSuggestion();
    const actions = [];
    const registering = newPasswords.includes(passwordField);
    if (registering) {
      actions.push(["Generate and fill password", () => {
        const password = generatePassword(newPasswords);
        generated.set(scope, password);
        for (const input of newPasswords) fill(input, password);
      }]);
    } else if (passwordField || usernameFocused) {
      for (const account of accounts.filter(({hasPassword}) => hasPassword)) {
        if (passwordField) {
          actions.push(["Fill password for " + account.username, async () => {
            const chosen = await send("site-password", {id: account.id});
            fill(username, chosen.username);
            fill(passwordField, chosen.password);
          }]);
        } else {
          actions.push(["Fill username for " + account.username, () => fill(field, account.username)]);
        }
      }
    }
    if (passwordField) {
      actions.push(["Save entered password", () => {
        if (!passwordField.value) {
          passwordField.focus();
          showNotice("Enter a password to save.");
          return;
        }
        return saveFormPassword(username?.value.trim() ?? "", passwordField.value);
      }]);
    }
    if (otp) {
      for (const account of accounts.filter(({hasTotp}) => hasTotp)) {
        actions.push(["Fill TOTP for " + account.username, async () => fill(field, await send("site-totp", {id: account.id}))]);
      }
    }
    if (conditional) actions.push(["Sign in with a passkey", conditional.run]);
    const note = registering ? "The generated password is saved when you submit the form." :
      usernameFocused && !passwordField ? "Select the password field to generate or save a password." : "";
    if (!actions.length && !note) return removeSuggestion();

    suggestion = makePopup();
    updateNoticeVisibility();
    suggestion.section.appendChild(document.createElement("strong")).textContent = "bigmouth";
    if (note) suggestion.section.appendChild(document.createElement("p")).textContent = note;
    for (const [label, action] of actions) {
      addButton(suggestion, label, () => {
        removeSuggestion();
        return action();
      });
    }
    addButton(suggestion, "Close", removeSuggestion);
  }

  document.addEventListener("focusin", (event) => {
    if (event.target === suggestion?.host || event.target === notice?.host) return;
    void suggest(event.target).catch(() => {});
  }, true);
  document.addEventListener("pointerdown", (event) => {
    if (event.target !== suggestion?.host && event.target !== suggestionField) removeSuggestion();
  }, true);
  document.addEventListener("click", (event) => {
    if (event.isTrusted && event.target === document.activeElement && event.target !== suggestionField &&
        event.target instanceof HTMLInputElement) {
      void suggest(event.target).catch(() => {});
    }
  }, true);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") removeSuggestion();
  }, true);

  async function saveFormPassword(username, password, generated = false) {
    await send("site-save-password", {username, password, generated});
    showNotice("Account saved.");
  }

  function passwordSubmitted(scope) {
    const field = newFields(scope)[0];
    const username = usernameField(scope)?.value.trim() ?? "";
    if (!field?.value) return;
    const password = field.value;
    const marker = submitted.get(scope);
    if (marker && marker.username === username && marker.password === password && Date.now() - marker.at < 1500) return;
    submitted.set(scope, {username, password, at: Date.now()});
    void saveFormPassword(username, password, generated.get(scope) === password).catch((error) => {
      if (document.body) showNotice(error.message);
    });
  }

  document.addEventListener("submit", (event) => {
    if (event.isTrusted && event.target instanceof HTMLFormElement) passwordSubmitted(event.target);
  }, true);
  document.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest('button,[role="button"],input[type="button"]') : null;
    if (event.isTrusted && button && !button.form && /sign\s*up|register|create\s*account|\u65b0\u898f\u767b\u9332|\u767b\u9332\u3059\u308b/i.test(button.textContent || button.value)) {
      passwordSubmitted(button.closest('[role="form"]') ?? document);
    }
  }, true);

  function accountSelect(form, label, choices, preferred) {
    const fieldLabel = form.appendChild(document.createElement("label"));
    fieldLabel.textContent = label;
    const field = fieldLabel.appendChild(document.createElement("select"));
    field.required = true;
    if (choices.length > 1 && !preferred) field.append(new Option("Select an account", ""));
    for (const choice of choices) field.append(new Option(choice.label, choice.id));
    if (preferred) field.value = preferred;
    return field;
  }

  function addConfirmation(form, label, confirm, cancel) {
    const save = form.appendChild(document.createElement("button"));
    save.type = "submit";
    save.textContent = label;
    const back = addButton({section: form}, "Cancel", cancel);
    const status = form.appendChild(document.createElement("p"));
    status.setAttribute("role", "status");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!event.isTrusted || save.disabled) return;
      save.disabled = back.disabled = true;
      status.textContent = "";
      try {
        await confirm();
      } catch (error) {
        status.textContent = error.message;
      } finally {
        save.disabled = back.disabled = false;
      }
    });
  }

  function showTotpForm(widget, value, {label, choices, preferred}, cancel) {
    widget.section.replaceChildren();
    widget.section.appendChild(document.createElement("p")).textContent = location.origin;
    const form = widget.section.appendChild(document.createElement("form"));
    let field;
    if (choices.length) {
      if (label) form.appendChild(document.createElement("p")).textContent = "QR code for " + label;
      field = accountSelect(form, "Save to account", choices, preferred);
    } else {
      const fieldLabel = form.appendChild(document.createElement("label"));
      fieldLabel.textContent = "Username";
      field = fieldLabel.appendChild(document.createElement("input"));
      field.required = true;
      field.autocomplete = "off";
      field.maxLength = 512;
      field.value = label;
    }
    addConfirmation(form, "Save TOTP", async () => {
      const target = choices.length ? {accountId: field.value} : {username: field.value};
      await send("site-save-totp", {value, ...target});
      if (widget.host.isConnected) showNotice("TOTP saved.");
    }, cancel);
    field.focus();
  }

  function offerTotp(value) {
    if (!/^otpauth:\/\/totp\//i.test(value) || seenCodes.has(value)) return;
    seenCodes.add(value);
    function detected() {
      const widget = showNotice("TOTP QR code detected.", "Save to an account", async () => {
        const targets = await send("site-totp-targets", {value});
        if (widget.host.isConnected) showTotpForm(widget, value, targets, detected);
      });
    }
    detected();
  }

  async function scan() {
    if (scanning || document.hidden || !document.body) return;
    scanning = true;
    try {
      await send("site-status");
      for (const link of document.querySelectorAll('a[href^="otpauth://totp/"]')) offerTotp(link.href);
      let examined = 0;
      for (const element of document.querySelectorAll("img, canvas, svg")) {
        if (examined === 8) break;
        const {width, height} = element.getBoundingClientRect();
        if (width < 50 || height < 50 || width / height > 1.55 || height / width > 1.55) continue;
        const stamp = element instanceof HTMLImageElement ? element.currentSrc :
          element instanceof SVGElement ? element.innerHTML : null;
        if (stamp && scannedImages.get(element) === stamp) continue;
        if (element instanceof HTMLImageElement && !element.naturalWidth) continue;
        if (stamp) scannedImages.set(element, stamp);
        examined++;
        const canvas = document.createElement("canvas");
        const scale = Math.min(2, 520 / Math.max(width, height));
        canvas.width = Math.round(width * scale);
        canvas.height = Math.round(height * scale);
        const context = canvas.getContext("2d", {willReadFrequently: true});
        let temporaryUrl;
        try {
          let source = element;
          if (element instanceof SVGElement) {
            temporaryUrl = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(element)], {type: "image/svg+xml"}));
            source = new Image();
            source.src = temporaryUrl;
            await source.decode();
          }
          context.drawImage(source, 0, 0, canvas.width, canvas.height);
          const image = context.getImageData(0, 0, canvas.width, canvas.height);
          const value = globalThis.decodeTotpQr(image);
          if (value) offerTotp(value);
        } catch {
          // Some embedded images do not expose their pixels to the document.
        } finally {
          if (temporaryUrl) URL.revokeObjectURL(temporaryUrl);
        }
      }
    } catch {
      // The current site may have been removed from the extension allowlist.
    } finally {
      scanning = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => { void scan(); }, {once: true});
  window.addEventListener("load", () => { void scan(); }, {once: true});
  setInterval(() => { void scan(); }, 2000);

  function reply(id, result) {
    window.postMessage({channel, direction: "from-extension", id, ...result}, location.origin);
  }

  function closePasskeyPrompt(bridgeId) {
    if (passkeyPrompt?.bridgeId !== bridgeId) return;
    clearInterval(passkeyPrompt.timer);
    passkeyPrompt.widget.host.remove();
    passkeyPrompt = null;
    updateNoticeVisibility();
  }

  function showPasskeyPrompt({bridgeId, view}) {
    removeSuggestion();
    const widget = makePopup();
    const timer = setInterval(() => { void send("site-status").catch(() => {}); }, 15_000);
    passkeyPrompt = {bridgeId, widget, timer};
    updateNoticeVisibility();
    widget.section.appendChild(document.createElement("strong")).textContent = view.title;
    widget.section.appendChild(document.createElement("p")).textContent = location.origin;
    if (view.detail) widget.section.appendChild(document.createElement("p")).textContent = view.detail;
    const form = widget.section.appendChild(document.createElement("form"));
    const account = accountSelect(form, "Account", view.choices, view.preferred);
    let verify;
    if (view.verification === "preferred") {
      const label = form.appendChild(document.createElement("label"));
      label.className = "check";
      verify = label.appendChild(document.createElement("input"));
      verify.type = "checkbox";
      label.append("Simulate successful user verification");
    }
    addConfirmation(form, "Continue", () => send("site-passkey-approve", {
      bridgeId, choice: account.value, verified: verify?.checked ?? false,
    }), () => send("site-passkey-cancel", {bridgeId}));
    account.focus();
  }

  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== chrome.runtime.id || message?.action !== "passkey-prompt") return;
    const request = bridgeRequests.get(message.bridgeId);
    if (!request || request.canceled || passkeyPrompt) return respond(false);
    showPasskeyPrompt(message);
    respond(true);
  });

  window.addEventListener("message", (event) => {
    const {data} = event;
    if (event.source !== window || event.origin !== location.origin || data?.channel !== channel ||
        data.direction !== "from-page" || typeof data.id !== "string") return;
    const {id, method, options} = data;
    if (data.cancel) {
      pendingPasskeys.delete(id);
      const request = bridgeRequests.get(id);
      if (request) request.canceled = true;
      bridgeRequests.delete(id);
      removeSuggestion();
      closePasskeyPrompt(id);
      void send("site-passkey-cancel", {bridgeId: id}).catch(() => {});
      return;
    }
    if (bridgeRequests.has(id)) return;
    const request = {canceled: false};
    bridgeRequests.set(id, request);
    reply(id, {ack: true});
    const answer = (result) => {
      bridgeRequests.delete(id);
      if (!request.canceled) reply(id, result);
    };
    const run = async () => {
      try {
        pendingPasskeys.delete(id);
        const value = await send("site-passkey", {bridgeId: id, method, options});
        answer({value});
      } catch (error) {
        answer({error: error.message, name: error.name});
      } finally {
        closePasskeyPrompt(id);
      }
    };
    void (async () => {
      try {
        await send("site-status");
        if (request.canceled) return;
        if (data.capability) return answer({value: true});
        if (!["create", "get"].includes(method) || !document.featurePolicy.allowsFeature("publickey-credentials-" + method)) {
          return answer({value: {fallback: true}});
        }
        if (method === "get" && data.mediation === "conditional") {
          if (!await send("site-conditional", {options})) return answer({value: {fallback: true}});
          if (request.canceled) return;
          pendingPasskeys.set(id, {run});
          return suggest(document.activeElement);
        }
        return run();
      } catch {
        answer({value: {fallback: true}});
      }
    })();
  });
})();
