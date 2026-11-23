import {signablePasskeys} from "./authenticator.js";
import {normalizeOrigin, normalizeOrigins} from "./origins.js";
import {approvePasskey, cancelPasskey, cancelPasskeysForTab, hasMatchingPasskey, requestPasskey} from "./passkeys.js";
import {configuredOrigins, requireSite, siteFor, updateScripts} from "./sites.js";
import {currentTotp, parseTotp} from "./totp.js";
import {accountFor, accountsForOrigin, changeVault, readVault, requireAccount, usernameValue} from "./vault.js";

const extensionUrl = chrome.runtime.getURL("");
const passwordPrompts = new Map();
const storageReady = chrome.storage.local.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"});

async function dashboard() {
  return {
    origins: await configuredOrigins(),
    accounts: (await readVault()).accounts.map((account) => ({
      id: account.id,
      origin: account.origin,
      username: account.username,
      hasPassword: Boolean(account.password),
      totp: account.totp,
      passkeys: signablePasskeys(account).map(({id}) => id),
    })),
  };
}

function canceled() {
  return new DOMException("The operation was canceled.", "NotAllowedError");
}

function finishPasswordPrompt(id, username, error) {
  const prompt = passwordPrompts.get(id);
  if (!prompt) return;
  passwordPrompts.delete(id);
  clearTimeout(prompt.timer);
  if (prompt.windowId != null) void chrome.windows.remove(prompt.windowId).catch(() => {});
  if (error) prompt.reject(error);
  else prompt.resolve(username);
}

function cancelPasswordPrompt(id) {
  finishPasswordPrompt(id, null, canceled());
}

function askPassword(site, username) {
  const id = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => cancelPasswordPrompt(id), 90_000);
    const prompt = {site, username, resolve, reject, timer};
    passwordPrompts.set(id, prompt);
    chrome.windows.create({
      url: chrome.runtime.getURL("prompt.html") + "#" + id,
      type: "popup",
      width: 430,
      height: 440,
      focused: true,
    }).then(({id: windowId}) => {
      if (passwordPrompts.has(id)) {
        prompt.windowId = windowId;
      } else {
        void chrome.windows.remove(windowId).catch(() => {});
      }
    }, (error) => finishPasswordPrompt(id, null, error));
  });
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [id, prompt] of passwordPrompts) {
    if (prompt.windowId === windowId) cancelPasswordPrompt(id);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  cancelPasskeysForTab(tabId);
  for (const [id, prompt] of passwordPrompts) {
    if (prompt.site.tabId === tabId) cancelPasswordPrompt(id);
  }
});

chrome.tabs.onUpdated.addListener((tabId, {status}) => {
  if (status === "loading") cancelPasskeysForTab(tabId);
});

async function savePassword(site, message) {
  let username = message.username?.trim() ? usernameValue(message.username) : "";
  if (typeof message.password !== "string" || !message.password || message.password.length > 4096) {
    throw new Error("Enter a password to save.");
  }
  const accounts = accountsForOrigin(await readVault(), site.origin);
  const existing = accounts.find((account) => account.username === username && account.password);
  if (existing?.password === message.password) return;
  if (!username || !message.generated || existing) username = await askPassword(site, username);
  await requireSite(site.origin);
  await changeVault((data) => {
    accountFor(data, site.origin, username).password = message.password;
  });
}

async function totpTargets(site, input) {
  const {label} = parseTotp(input);
  const choices = accountsForOrigin(await readVault(), site.origin)
    .map(({id, username}) => ({id, label: username}));
  return {label, choices, preferred: choices.find((choice) => choice.label === label)?.id};
}

async function saveTotp(site, {value, accountId, username}) {
  const totp = parseTotp(value);
  await changeVault((data) => {
    const account = accountId ? requireAccount(data, accountId, site.origin)
      : accountFor(data, site.origin, usernameValue(username));
    account.totp = totp;
  });
}

async function fromSite(message, site) {
  switch (message.action) {
    case "site-status":
      return true;
    case "site-accounts":
      return accountsForOrigin(await readVault(), site.origin).map(({id, username, password, totp}) => ({
        id, username, hasPassword: Boolean(password), hasTotp: Boolean(totp),
      }));
    case "site-password": {
      const {username, password} = requireAccount(await readVault(), message.id, site.origin);
      if (!password) throw new Error("This account has no saved password.");
      return {username, password};
    }
    case "site-save-password":
      return savePassword(site, message);
    case "site-totp-targets":
      return totpTargets(site, message.value);
    case "site-save-totp":
      return saveTotp(site, message);
    case "site-totp": {
      const {totp} = requireAccount(await readVault(), message.id, site.origin);
      if (!totp) throw new Error("This account has no saved TOTP.");
      return currentTotp(totp);
    }
    case "site-conditional":
      return hasMatchingPasskey(site, message.options);
    case "site-passkey":
      return requestPasskey(site, message);
    case "site-passkey-approve":
      return approvePasskey(site, message);
    case "site-passkey-cancel":
      return cancelPasskey(site, message.bridgeId);
    default:
      throw new Error("Unknown site action.");
  }
}

async function saveAccount(message) {
  const origin = normalizeOrigin(message.origin);
  const username = usernameValue(message.username);
  const totp = message.totp ? parseTotp(message.totp) : null;
  return changeVault((data) => {
    const account = accountFor(data, origin, username);
    if (message.password) account.password = message.password;
    if (totp) account.totp = totp;
  });
}

async function fromExtension(message) {
  switch (message.action) {
    case "dashboard":
      return dashboard();
    case "set-sites":
      return updateScripts(normalizeOrigins(message.origins));
    case "save-account":
      return saveAccount(message);
    case "delete-account":
      return changeVault((data) => {
        data.accounts = data.accounts.filter(({id}) => id !== message.id);
      });
    case "delete-passkey":
      return changeVault((data) => {
        const account = requireAccount(data, message.id);
        account.passkeys = account.passkeys.filter(({id}) => id !== message.credentialId);
      });
    case "copy-password":
      return requireAccount(await readVault(), message.id).password;
    case "prompt": {
      const prompt = passwordPrompts.get(message.id);
      if (!prompt) throw canceled();
      return {origin: prompt.site.origin, username: prompt.username};
    }
    case "approve": {
      const prompt = passwordPrompts.get(message.id);
      if (!prompt) throw canceled();
      return finishPasswordPrompt(message.id, prompt.username || usernameValue(message.username));
    }
    case "cancel":
      return cancelPasswordPrompt(message.id);
    case "keepalive":
      return passwordPrompts.has(message.id);
    default:
      throw new Error("Unknown extension action.");
  }
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || !message?.action) return false;
  storageReady.then(async () => sender.url?.startsWith(extensionUrl)
    ? fromExtension(message) : fromSite(message, await siteFor(sender)))
    .then((value) => reply({value}), (error) => reply({error: error.message, name: error.name}));
  return true;
});
