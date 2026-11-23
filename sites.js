import {defaultOrigins, injectionMatches, matchesOrigin} from "./origins.js";

const scriptIds = ["allowed-sites", "webauthn-page"];
let updates = Promise.resolve();

export async function configuredOrigins() {
  return (await chrome.storage.local.get({origins: defaultOrigins})).origins;
}

export function updateScripts(origins) {
  const update = updates.then(async () => {
    const previous = await configuredOrigins();
    const desired = injectionMatches(origins ?? previous);
    if (origins) await chrome.storage.local.set({origins});
    const matches = [];
    for (const pattern of desired) {
      if (await chrome.permissions.contains({origins: [pattern]})) matches.push(pattern);
    }
    const current = await chrome.scripting.getRegisteredContentScripts({ids: scriptIds});
    const scripts = matches.length ? [
      {id: scriptIds[0], matches, js: ["qr.js", "content.js"], runAt: "document_start", world: "ISOLATED"},
      {id: scriptIds[1], matches, js: ["webauthn-page.js"], runAt: "document_start", world: "MAIN"},
    ] : [];
    if (current.length === scriptIds.length && scripts.length) {
      await chrome.scripting.updateContentScripts(scripts);
    } else {
      if (current.length) await chrome.scripting.unregisterContentScripts({ids: current.map(({id}) => id)});
      if (scripts.length) await chrome.scripting.registerContentScripts(scripts);
    }
    if (origins) {
      const removed = injectionMatches(previous).filter((pattern) => !desired.includes(pattern));
      if (removed.length) await chrome.permissions.remove({origins: removed});
    }
  });
  updates = update.catch(() => {});
  return update;
}

function syncScripts() {
  void updateScripts().catch(console.error);
}

chrome.runtime.onInstalled.addListener(syncScripts);
chrome.permissions.onAdded.addListener(syncScripts);
chrome.permissions.onRemoved.addListener(syncScripts);

export async function requireSite(origin) {
  if (!matchesOrigin(origin, await configuredOrigins()) ||
      !await chrome.permissions.contains({origins: injectionMatches([origin])})) {
    throw new DOMException("This site is not on the extension's allowlist.", "NotAllowedError");
  }
}

export async function siteFor(sender) {
  if (!sender.tab || sender.frameId !== 0 || !sender.url) {
    throw new DOMException("This action requires an allowed top-level page.", "NotAllowedError");
  }
  const {origin, hostname} = new URL(sender.url);
  await requireSite(origin);
  return {origin, hostname, tabId: sender.tab.id, documentId: sender.documentId};
}
