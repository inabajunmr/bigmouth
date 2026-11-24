import {signablePasskeys} from "./authenticator.js";
import {normalizeOrigin, normalizeOrigins} from "./origins.js";
import {approvePasskey, cancelPasskey, cancelPasskeysForTab, hasMatchingPasskey, requestPasskey} from "./passkeys.js";
import {configuredOrigins, siteFor, updateScripts} from "./sites.js";
import {currentTotp, parseTotp} from "./totp.js";
import {accountFor, accountsForOrigin, changeVault, readVault, requireAccount, usernameValue} from "./vault.js";

const extensionUrl = chrome.runtime.getURL("");
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
      note: account.note,
      passkeys: signablePasskeys(account).map(({id}) => id),
    })),
  };
}

chrome.tabs.onRemoved.addListener(cancelPasskeysForTab);

chrome.tabs.onUpdated.addListener((tabId, {status}) => {
  if (status === "loading") cancelPasskeysForTab(tabId);
});

async function savePassword({origin}, {accountId, username, password, generated}) {
  if (typeof password !== "string" || !password || password.length > 4096) {
    throw new Error("Enter a password to save.");
  }
  return changeVault((data) => {
    if (accountId) {
      requireAccount(data, accountId, origin).password = password;
      return true;
    }
    const name = usernameValue(username);
    const existing = accountsForOrigin(data, origin).find((account) => account.username === name);
    if (existing && generated !== true) {
      throw new Error("An account with this username already exists. Select it to save the password.");
    }
    if (existing?.password && existing.password !== password) return false;
    (existing ?? accountFor(data, origin, name)).password = password;
    return true;
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
    if (typeof message.note === "string") {
      if (message.note.trim()) account.note = message.note;
      else delete account.note;
    }
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
