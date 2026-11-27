import {injectionMatches, normalizeOrigins} from "./origins.js";
import {currentTotp, formatTotp, totpSnapshot} from "./totp.js";
import {vaultStorageKey} from "./vault.js";

const status = document.querySelector("#status");
const sites = document.querySelector("#sites");
const siteStatus = document.querySelector("#site-status");
const origins = document.querySelector("#origins");
const accountForm = document.querySelector("#account-form");
const originField = accountForm.elements.origin;
const passwordField = accountForm.elements.password;
const totpField = accountForm.elements.totp;
const noteField = accountForm.elements.note;
const filter = document.querySelector("#filter");
const list = document.querySelector("#accounts");
const initialOrigin = chrome.tabs.query({active: true, currentWindow: true}).then(([tab]) => {
  if (!tab?.url) return "";
  const {origin, protocol} = new URL(tab.url);
  return protocol === "http:" || protocol === "https:" ? origin : "";
}).catch(() => "");
const totpRows = [];
let dashboard;
let dashboardVersion = 0;
let editVersion = 0;
let displayedPassword = "";
let displayedTotp = "";
let displayedNote = "";

async function request(action, detail = {}) {
  const response = await chrome.runtime.sendMessage({action, ...detail});
  if (response?.error) throw new Error(response.error);
  return response?.value;
}

function actionButton(container, label, action) {
  const button = container.appendChild(document.createElement("button"));
  button.type = "button";
  button.className = "secondary";
  button.textContent = label;
  button.addEventListener("click", () => perform(action));
  return button;
}

async function refreshTotpRow(row) {
  row.pending = true;
  try {
    const {code, expiresAt} = await totpSnapshot(row.record);
    const now = Date.now();
    if (expiresAt > now) {
      row.expiresAt = expiresAt;
      row.code.textContent = code;
      row.remaining.textContent = `${Math.ceil((expiresAt - now) / 1000)}s left`;
      row.copy.disabled = false;
    }
  } catch (error) {
    row.failed = true;
    row.code.textContent = "Error";
    row.remaining.textContent = error.message;
    row.copy.disabled = true;
  } finally {
    row.pending = false;
  }
}

function updateTotp() {
  const now = Date.now();
  for (const row of totpRows) {
    if (row.failed) continue;
    if (row.expiresAt > now) {
      const remaining = `${Math.ceil((row.expiresAt - now) / 1000)}s left`;
      if (row.remaining.textContent !== remaining) row.remaining.textContent = remaining;
    } else if (!row.pending) {
      row.code.textContent = "Updating";
      row.remaining.textContent = "";
      void refreshTotpRow(row);
    }
  }
}

function renderAccounts() {
  const query = filter.value.toLowerCase().trim();
  const exactOrigin = query === filter.defaultValue ? query : "";
  list.replaceChildren();
  totpRows.length = 0;
  for (const account of dashboard.accounts.filter(({origin, username}) =>
    exactOrigin ? origin === exactOrigin : (origin + " " + username).toLowerCase().includes(query))) {
    const card = list.appendChild(document.createElement("article"));
    card.appendChild(document.createElement("h2")).textContent = account.username;
    const meta = card.appendChild(document.createElement("p"));
    meta.className = "subtitle";
    meta.textContent = account.origin + " / Passkeys (" + account.passkeys.length + ")";
    if (account.totp) {
      const row = card.appendChild(document.createElement("div"));
      row.className = "totp";
      row.appendChild(document.createElement("span")).textContent = "TOTP";
      const code = row.appendChild(document.createElement("code"));
      const remaining = row.appendChild(document.createElement("span"));
      remaining.className = "hint";
      const copy = actionButton(row, "Copy TOTP", async () => {
        await navigator.clipboard.writeText(await currentTotp(account.totp));
        await request("record-account-use", {id: account.id});
        status.textContent = "TOTP copied.";
      });
      copy.disabled = true;
      totpRows.push({record: account.totp, code, remaining, copy, expiresAt: 0});
    }
    const actions = card.appendChild(document.createElement("div"));
    actions.className = "actions";
    if (account.hasPassword) actionButton(actions, "Copy password", async () => {
      await navigator.clipboard.writeText(await request("copy-password", {id: account.id}));
      await request("record-account-use", {id: account.id});
      status.textContent = "Password copied.";
    });
    actionButton(actions, "Edit", async () => {
      const version = ++editVersion;
      const password = account.hasPassword ? await request("copy-password", {id: account.id}) : "";
      if (version !== editVersion) return;
      accountForm.reset();
      accountForm.parentElement.open = true;
      originField.value = account.origin;
      accountForm.elements.username.value = account.username;
      passwordField.type = "text";
      displayedPassword = password ?? "";
      passwordField.value = displayedPassword;
      displayedTotp = account.totp ? formatTotp(account.totp) : "";
      totpField.value = displayedTotp;
      noteField.value = account.note ?? "";
      displayedNote = noteField.value;
      passwordField.focus();
    });
    actionButton(actions, "Delete", async () => {
      if (!window.confirm("Remove " + account.username + " from the vault?")) return;
      await request("delete-account", {id: account.id});
    });
    for (const credentialId of account.passkeys) {
      const row = card.appendChild(document.createElement("div"));
      row.className = "actions";
      const label = row.appendChild(document.createElement("code"));
      label.textContent = credentialId.slice(0, 8);
      actionButton(row, "Delete passkey", async () => {
        if (!window.confirm("Delete this local passkey?")) return;
        await request("delete-passkey", {id: account.id, credentialId});
      });
    }
  }
  if (!list.childElementCount) {
    const message = list.appendChild(document.createElement("p"));
    message.className = "hint";
    message.textContent = query ? "No matching accounts." : "No saved accounts.";
  }
  updateTotp();
}

async function refresh() {
  const version = ++dashboardVersion;
  const [current, origin] = await Promise.all([request("dashboard"), initialOrigin]);
  if (version !== dashboardVersion) return;
  const firstLoad = !dashboard;
  if (firstLoad) filter.defaultValue = origin;
  dashboard = current;
  renderAccounts();
  if (firstLoad) {
    if (!origins.value) origins.value = dashboard.origins.join("\n");
    const matches = injectionMatches(dashboard.origins);
    sites.open ||= matches.length === 0;
    if (matches.length && !await chrome.permissions.contains({origins: matches})) {
      sites.open = true;
      siteStatus.textContent = "Save again and grant site access in Chrome to enable these sites.";
    }
  }
}

function perform(operation, button = null, feedback = status) {
  feedback.textContent = "";
  if (button) button.disabled = true;
  void Promise.resolve(operation()).catch((error) => {
    feedback.textContent = error.message;
  }).finally(() => {
    if (button) button.disabled = false;
  });
}

document.querySelector("#site-form").addEventListener("submit", (event) => {
  event.preventDefault();
  perform(async () => {
    const entered = origins.value;
    const values = normalizeOrigins(entered);
    const normalized = values.join("\n");
    const matches = injectionMatches(values);
    // Chrome's permission dialog can outlive the toolbar popup.
    const saved = request("set-sites", {origins: normalized});
    const permission = matches.length ? chrome.permissions.request({origins: matches}) : Promise.resolve(true);
    await Promise.all([saved, permission]);
    if (origins.value === entered) origins.value = normalized;
    const granted = !matches.length || await chrome.permissions.contains({origins: matches});
    siteStatus.textContent = granted
      ? "Allowed sites saved. Reload any open pages to apply the changes."
      : "Allowed sites saved. Grant site access in Chrome to enable them.";
  }, event.submitter, siteStatus);
});

void initialOrigin.then((origin) => {
  originField.defaultValue = origin;
});

accountForm.addEventListener("submit", (event) => {
  event.preventDefault();
  perform(async () => {
    const version = ++editVersion;
    const fields = Object.fromEntries(new FormData(accountForm));
    if (fields.password === displayedPassword) delete fields.password;
    if (fields.totp === displayedTotp) delete fields.totp;
    if (fields.note === displayedNote) delete fields.note;
    await request("save-account", fields);
    if (version === editVersion) {
      displayedPassword = "";
      displayedTotp = "";
      displayedNote = "";
      accountForm.reset();
      passwordField.type = "password";
    }
    status.textContent = "Account saved.";
  }, event.submitter);
});

filter.addEventListener("input", () => {
  if (dashboard) renderAccounts();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[vaultStorageKey]) void refresh().catch((error) => { status.textContent = error.message; });
});
setInterval(updateTotp, 250);
perform(refresh);
