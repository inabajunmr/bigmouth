export const vaultStorageKey = "testVaultByOrigin";

let writes = Promise.resolve();

function serialized(task) {
  const next = writes.then(task);
  writes = next.catch(() => {});
  return next;
}

async function loadVault() {
  const stored = await chrome.storage.local.get({[vaultStorageKey]: {accounts: []}});
  return stored[vaultStorageKey];
}

export async function readVault() {
  await writes;
  return loadVault();
}

export function changeVault(change) {
  return serialized(async () => {
    const data = await loadVault();
    const result = await change(data);
    await chrome.storage.local.set({[vaultStorageKey]: data});
    return result;
  });
}

export function usernameValue(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 512) {
    throw new Error("Enter a username.");
  }
  return value.trim();
}

export function accountsForOrigin({accounts}, origin) {
  return accounts.filter((account) => account.origin === origin);
}

export function accountFor(data, origin, username) {
  let account = data.accounts.find((item) => item.origin === origin && item.username === username);
  if (!account) {
    account = {id: crypto.randomUUID(), origin, username, passkeys: []};
    data.accounts.push(account);
  }
  return account;
}

export function requireAccount(data, id, origin) {
  const account = data.accounts.find((item) => item.id === id && (origin === undefined || item.origin === origin));
  if (!account) throw new Error("Account not found.");
  return account;
}
