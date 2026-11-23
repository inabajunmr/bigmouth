const id = location.hash.slice(1);
const status = document.querySelector("#status");
const form = document.querySelector("#confirm");
const username = document.querySelector("#username");
const approve = document.querySelector("#approve");
const cancel = document.querySelector("#cancel");

async function request(action, fields = {}) {
  const reply = await chrome.runtime.sendMessage({action, id, ...fields});
  if (reply?.error) throw new Error(reply.error);
  return reply?.value;
}

try {
  const view = await request("prompt");
    document.querySelector("#origin").textContent = view.origin;
  document.querySelector("#detail").textContent = view.username;
  document.querySelector("#username-row").hidden = Boolean(view.username);
  username.required = !view.username;
  form.hidden = false;
} catch (error) {
  status.textContent = error.message;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  approve.disabled = true;
  try {
    await request("approve", {username: username.value});
  } catch (error) {
    status.textContent = error.message;
  } finally {
    approve.disabled = false;
  }
});

cancel.addEventListener("click", () => { void request("cancel").catch(() => {}); });
setInterval(() => { void request("keepalive").catch(() => {}); }, 15_000);
