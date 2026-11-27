import {createResponse, fromBase64Url, getResponse, registrationRecord, signablePasskeys} from "./authenticator.js";
import {requireSite} from "./sites.js";
import {
  accountChoices, accountFor, accountsForOrigin, changeVault, markAccountUsed,
  readVault, recordAccountUse, requireAccount, usernameValue,
} from "./vault.js";

const activeRequests = new Map();

function requestKey(site, bridgeId) {
  return JSON.stringify([site.tabId, site.documentId, bridgeId]);
}

function canceled() {
  return new DOMException("The operation was canceled.", "NotAllowedError");
}

function finishApproval(request, answer, error) {
  const approval = request.approval;
  if (!approval) return;
  request.approval = null;
  clearTimeout(approval.timer);
  if (error) approval.reject(error);
  else approval.resolve(answer);
}

function cancelRequest(request) {
  request.canceled = true;
  finishApproval(request, null, canceled());
}

function ask(request, view, deadline) {
  const {site, bridgeId} = request;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => cancelRequest(request), deadline - Date.now());
    request.approval = {view, timer, resolve, reject};
    const message = {action: "passkey-prompt", bridgeId, view};
    void chrome.tabs.sendMessage(site.tabId, message, {documentId: site.documentId}).then((shown) => {
      if (!shown) cancelRequest(request);
    }, () => cancelRequest(request));
  });
}

export function approvePasskey(site, {bridgeId, choice, verified}) {
  const request = activeRequests.get(requestKey(site, bridgeId));
  const view = request?.approval?.view;
  if (!view) throw canceled();
  if (!view.choices.some(({id}) => id === choice)) throw new Error("Select an account.");
  finishApproval(request, {
    choice,
    verified: view.verification === "required" || (view.verification === "preferred" && verified === true),
  });
}

export function cancelPasskey(site, bridgeId) {
  const request = activeRequests.get(requestKey(site, bridgeId));
  if (request) cancelRequest(request);
}

export function cancelPasskeysForTab(tabId) {
  for (const request of activeRequests.values()) {
    if (request.site.tabId === tabId) cancelRequest(request);
  }
}

function platformOptions({hostname}, method, options) {
  if (!options || typeof options.challenge !== "string" || !fromBase64Url(options.challenge).length) {
    throw new DOMException("The WebAuthn challenge is missing.", "TypeError");
  }
  const rpId = method === "create" ? options.rp?.id ?? hostname : options.rpId ?? hostname;
  if (typeof rpId !== "string" || rpId.toLowerCase() !== hostname) return null;
  if (method === "get") return {...options, rpId: hostname};

  const params = options.pubKeyCredParams ?? [];
  if (options.authenticatorSelection?.authenticatorAttachment === "cross-platform" ||
      (params.length && !params.some(({type, alg}) => type === "public-key" && alg === -7)) ||
      options.extensions?.largeBlob?.support === "required" ||
      options.extensions?.enforceCredentialProtectionPolicy || options.extensions?.payment) {
    return null;
  }
  return {...options, rp: {...options.rp, id: hostname}};
}

function includesCredential(descriptors, id) {
  return descriptors?.some((item) => item.type === "public-key" && item.id === id);
}

function passkeyCandidates(accounts, options) {
  return accounts.flatMap((account) => signablePasskeys(account)
    .filter(({rpId, id}) => rpId === options.rpId && (!options.allowCredentials?.length ||
      includesCredential(options.allowCredentials, id)))
    .map((passkey) => ({account, passkey})));
}

export async function hasMatchingPasskey(site, options) {
  const platform = platformOptions(site, "get", options);
  if (!platform) return false;
  const accounts = accountsForOrigin(await readVault(), site.origin);
  return passkeyCandidates(accounts, platform).length > 0;
}

function checkExcludedCredentials(accounts, descriptors) {
  if (accounts.some((account) => signablePasskeys(account).some(({id}) => includesCredential(descriptors, id)))) {
    throw new DOMException("This passkey is already registered.", "InvalidStateError");
  }
}

async function authenticate(request, options, accounts, deadline) {
  const {site} = request;
  const candidates = passkeyCandidates(accounts, options);
  if (!candidates.length) return {fallback: true};
  const {choice, verified} = await ask(request, {
    title: "Sign in with a passkey",
    choices: candidates.map(({passkey, account}) => ({
      id: passkey.id,
      label: account.username,
    })),
    verification: options.userVerification ?? "preferred",
  }, deadline);
  await requireSite(site.origin);
  const currentAccounts = accountsForOrigin(await readVault(), site.origin);
  const current = passkeyCandidates(currentAccounts, options).find(({passkey}) => passkey.id === choice);
  if (request.canceled || !current) throw canceled();
  const response = await getResponse(options, site.origin, current.passkey, verified);
  if (request.canceled) throw canceled();
  await recordAccountUse(current.account.id, site.origin);
  return response;
}

async function register(request, options, accounts, deadline) {
  const {site} = request;
  const username = usernameValue(options.user?.name);
  const record = registrationRecord(options);
  checkExcludedCredentials(accounts, options.excludeCredentials);
  const choices = accountChoices(accounts);
  const {choice, verified} = await ask(request, {
    title: "Save passkey",
    detail: username,
    choices: [
      ...choices,
      {id: "new", label: username + " (new account)"},
    ],
    preferred: choices.find(({label}) => label === username)?.id ?? "new",
    verification: options.authenticatorSelection?.userVerification ?? "preferred",
  }, deadline);
  await requireSite(site.origin);
  const response = await createResponse(options, site.origin, record, verified);
  await changeVault((data) => {
    if (request.canceled) throw canceled();
    checkExcludedCredentials(accountsForOrigin(data, site.origin), options.excludeCredentials);
    const account = choice === "new" ? accountFor(data, site.origin, username) : requireAccount(data, choice, site.origin);
    account.passkeys = account.passkeys.filter(({rpId, userHandle}) =>
      rpId !== record.rpId || userHandle !== record.userHandle);
    account.passkeys.push(record);
    markAccountUsed(data, account);
  });
  return response;
}

export async function requestPasskey(site, {bridgeId, method, options}) {
  if (method !== "create" && method !== "get") throw new Error("Unknown passkey action.");
  const key = requestKey(site, bridgeId);
  if (activeRequests.has(key)) throw new Error("This request is already in progress.");
  const request = {site, bridgeId, canceled: false};
  activeRequests.set(key, request);
  try {
    const platform = platformOptions(site, method, options);
    if (!platform) return {fallback: true};
    const deadline = Date.now() + Math.min(120_000, Math.max(1_000, Number(platform.timeout) || 90_000));
    const accounts = accountsForOrigin(await readVault(), site.origin);
    if (request.canceled) throw canceled();
    if (method === "get") return await authenticate(request, platform, accounts, deadline);
    return await register(request, platform, accounts, deadline);
  } finally {
    activeRequests.delete(key);
  }
}
