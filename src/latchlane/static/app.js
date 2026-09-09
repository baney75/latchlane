"use strict";
const $ = (id) => document.getElementById(id);
const show = (id, yes = true) => $(id).classList.toggle("hidden", !yes);
let initialized = false,
  currentMode = "ask",
  chosenMode = "ask",
  setupToken = location.hash.slice(1),
  watching = null,
  copiedValue = null,
  editingKey = null,
  state = null,
  renderedSignature = null,
  pairTimer = null,
  pairGeneration = 0,
  deferredInstallPrompt = null,
  notifiedRequestIds = null,
  notificationsEnabled =
    localStorage.getItem("latchlane-notifications") === "yes";
const noticeTimers = new WeakMap();
history.replaceState(null, "", location.pathname + location.search);
const captureParams = new URLSearchParams(location.search);
const captureMode = captureParams.get("window") === "capture";

class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.status = status;
  }
}
function clearNotice(target) {
  clearTimeout(noticeTimers.get(target));
  target.classList.add("hidden");
  target.textContent = "";
  target.classList.remove("error");
}
function clearDialogNotices() {
  document.querySelectorAll(".dialog-notice").forEach(clearNotice);
  clearNotice($("notice"));
}
function notice(text, error = false) {
  const dialog = document.querySelector("dialog[open]");
  let target = $("notice");
  if (dialog) {
    target = dialog.querySelector(".dialog-notice");
    if (!target) {
      target = document.createElement("div");
      target.className = "dialog-notice";
      dialog.append(target);
    }
  }
  clearTimeout(noticeTimers.get(target));
  target.textContent = text;
  target.setAttribute("role", error ? "alert" : "status");
  target.classList.toggle("error", error);
  target.classList.remove("hidden");
  if (dialog) target.scrollIntoView({ block: "nearest" });
  noticeTimers.set(
    target,
    setTimeout(() => target.classList.add("hidden"), 6500),
  );
}
async function api(path, method = "GET", body) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Latchlane": "1",
        ...(setupToken ? { "X-Setup-Token": setupToken } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch (error) {
    throw new ApiError(
      "Cannot reach Latchlane. Check that its host is running, then retry.",
      0,
    );
  }
  let data = {};
  try {
    data = await response.json();
  } catch (error) {}
  if (!response.ok)
    throw new ApiError(
      data.detail || "Something went wrong. Try again.",
      response.status,
    );
  return data;
}
const sessionError = (error) =>
  error instanceof ApiError && (error.status === 401 || error.status === 423);
function node(tag, text, cls) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function button(text, fn, cls = "quiet", label) {
  const b = node("button", text, cls);
  b.type = "button";
  if (label) b.setAttribute("aria-label", label);
  b.onclick = async () => {
    if (b.disabled) return;
    b.disabled = true;
    try {
      await fn();
    } catch (error) {
      await handleActionError(error);
    } finally {
      b.disabled = false;
    }
  };
  return b;
}
function empty(target, title, description) {
  const box = node("div", undefined, "empty"),
    inner = node("div");
  inner.append(
    node("div", "↗", "empty-icon"),
    node("h3", title),
    node("p", description),
  );
  box.append(inner);
  target.append(box);
}
function formatRemaining(seconds) {
  const value = Math.max(0, Math.ceil(seconds));
  return value >= 60
    ? `${Math.floor(value / 60)}m ${String(value % 60).padStart(2, "0")}s`
    : `${value}s`;
}
function updatePendingExpiry() {
  document.querySelectorAll("[data-request-expiry]").forEach((el) => {
    const remaining =
      (Number(el.dataset.requestExpiry) * 1000 - Date.now()) / 1000;
    el.textContent =
      remaining > 0
        ? `Expires in ${formatRemaining(remaining)}`
        : "Expired — refresh to clear";
  });
}
function updateNotificationStatus() {
  if (!("Notification" in window)) {
    $("notifications").disabled = true;
    $("notification-status").textContent =
      "This browser does not support approval notifications.";
    return;
  }
  if (Notification.permission === "denied") {
    $("notifications").disabled = true;
    $("notification-status").textContent =
      "Notifications are blocked in this browser’s settings.";
    return;
  }
  $("notifications").textContent = notificationsEnabled
    ? "Turn off approval notifications"
    : "Enable approval notifications";
  if (notificationsEnabled)
    $("notification-status").textContent =
      "Enabled while this app stays open. Alerts show only a waiting-approval count.";
}
async function notifyPendingApprovals(count) {
  if (!notificationsEnabled || document.visibilityState !== "hidden") return;
  if (!("serviceWorker" in navigator)) return;
  const registration = await navigator.serviceWorker.ready;
  await registration.showNotification("Latchlane", {
    body: `${count} approval${count === 1 ? "" : "s"} waiting.`,
    tag: "latchlane-pending-approvals",
    renotify: true,
  });
}
function updatePendingNotifications(next) {
  const current = new Set(next.pending.map((request) => request.id));
  const newRequestIds = notifiedRequestIds
    ? [...current].filter((id) => !notifiedRequestIds.has(id))
    : [];
  notifiedRequestIds = current;
  if (newRequestIds.length)
    notifyPendingApprovals(next.pending.length).catch(() => {});
}
function operationText(operation, key) {
  if (operation.kind === "lease")
    return "RAW KEY ACCESS — this client can retain or reuse the key after release.";
  return `${operation.method} ${key?.origin || "Unknown origin"}${operation.path}${operation.body ? `\nBody: ${operation.body}` : ""}`;
}
function renderDashboard(next) {
  const previousClients = state?.clients?.length || 0;
  state = next;
  if (next.clients.length > previousClients) clearPairResult();
  show("welcome", false);
  show("dashboard");
  show("lock");
  show("logout");
  show("retry", false);
  currentMode = next.mode;
  document
    .querySelectorAll("[data-mode]")
    .forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.mode === currentMode)),
    );
  $("keys").replaceChildren();
  $("key-count").textContent = next.keys.length;
  for (const key of next.keys) {
    const row = node("div", undefined, "key-row"),
      meta = node("div", undefined, "key-meta"),
      text = node("div");
    text.append(node("strong", key.name), node("p", key.origin));
    meta.append(node("span", "↗", "key-symbol"), text);
    const actions = node("div", undefined, "key-actions");
    const details = document.createElement("details");
    details.className = "key-details";
    details.append(node("summary", "Details"));
    details.append(
      node(
        "p",
        `Authentication: ${key.header}${key.prefix ? ` (${key.prefix.trim()})` : " (no prefix)"}`,
      ),
      node(
        "p",
        key.safe_paths?.length
          ? `Trusted reads: ${key.safe_paths.join(", ")}`
          : "Trusted reads: none",
      ),
    );
    actions.append(
      button("Edit", () => openEdit(key), "quiet", `Edit ${key.name}`),
      button(
        "Remove",
        async () => {
          if (
            confirm(
              `Remove ${key.name}? This does not revoke the key at its provider.`,
            )
          ) {
            await api("/api/keys/" + encodeURIComponent(key.name), "DELETE");
            await refresh();
          }
        },
        "remove",
        `Remove ${key.name}`,
      ),
    );
    row.append(meta, actions);
    $("keys").append(row);
    $("keys").append(details);
  }
  if (!next.keys.length)
    empty(
      $("keys"),
      "Your first key belongs here.",
      "Add a key to give your agents a safe place to start.",
    );
  $("clients").replaceChildren();
  for (const client of next.clients) {
    const row = node("div", undefined, "client");
    row.append(
      node("span", client.name),
      button(
        "Revoke",
        async () => {
          if (confirm(`Revoke ${client.name}?`)) {
            await api("/api/clients/" + client.id, "DELETE");
            await refresh();
          }
        },
        "remove",
        `Revoke ${client.name}`,
      ),
    );
    $("clients").append(row);
  }
  show("approvals", next.pending.length > 0);
  $("pending-count").textContent = next.pending.length;
  $("requests").replaceChildren();
  for (const request of next.pending) {
    const operation = request.operation,
      key = next.keys.find((item) => item.name === operation.key),
      box = node("article", undefined, "request"),
      expiry = node("span", undefined, "request-expiry");
    expiry.dataset.requestExpiry = request.expires;
    box.append(
      node("h3", `${request.agent} wants to use ${operation.key}`),
      node("p", operation.purpose || "No purpose was supplied."),
      node("pre", operationText(operation, key)),
      expiry,
    );
    const actions = node("div", undefined, "actions");
    actions.append(
      button(
        "Approve once",
        async () => {
          await api(`/api/requests/${request.id}/decision`, "POST", {
            approve: true,
          });
          await refresh();
        },
        "primary",
        `Approve ${request.agent}'s request for ${operation.key} once`,
      ),
      button(
        "Deny",
        async () => {
          await api(`/api/requests/${request.id}/decision`, "POST", {
            approve: false,
          });
          await refresh();
        },
        "secondary",
        `Deny ${request.agent}'s request for ${operation.key}`,
      ),
    );
    box.append(actions);
    $("requests").append(box);
  }
  $("activity").replaceChildren();
  for (const activity of next.audit) {
    const row = node("div", undefined, "activity-row");
    row.append(
      node(
        "time",
        new Date(activity.time * 1000).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
      ),
      node("span", activity.event.replaceAll(":", " · ")),
      node("span", [activity.key, activity.agent].filter(Boolean).join(" / ")),
    );
    $("activity").append(row);
  }
  if (!next.audit.length)
    $("activity").append(
      node("p", "A quiet start. Your vault activity will appear here.", "fine"),
    );
  updatePendingExpiry();
  updatePendingNotifications(next);
}
async function refresh() {
  const next = await api("/api/owner");
  const signature = `${next.revision}:${next.pending
    .map((request) => request.id)
    .sort()
    .join(",")}`;
  if (signature !== renderedSignature) {
    renderDashboard(next);
    renderedSignature = signature;
  } else {
    state = next;
    updatePendingExpiry();
    updatePendingNotifications(next);
  }
  return next;
}
function presentWelcome(status) {
  initialized = status.initialized;
  show("dashboard", false);
  show("welcome");
  show("lock", false);
  show("logout", false);
  show("retry", false);
  $("entry-title").textContent = initialized
    ? "Good to have you back."
    : "Make yourself at home.";
  $("entry-description").textContent = initialized
    ? "Enter your passphrase to open the owner console. Your agents keep the access rules you chose."
    : status.initial_mode !== "ask"
      ? `Your host was explicitly configured for ${status.initial_mode === "yolo" ? "YOLO: paired agents can use all keys without asking." : "Auto approve: only trusted read routes skip approval."} Create a passphrase to protect the vault.`
      : "One passphrase protects your vault. You’ll start in Always ask, so every key use is your decision.";
  $("enter").textContent = initialized
    ? "Open my vault ↗"
    : "Create my vault ↗";
  $("password").minLength = initialized ? 1 : 14;
  $("password").autocomplete = initialized
    ? "current-password"
    : "new-password";
  show("confirm-wrap", !initialized);
  $("enter").disabled = !initialized && !setupToken;
  if (!initialized && !setupToken)
    $("entry-description").textContent =
      "Run “latchlane start” on the host to open your private setup window.";
}
function stopWatch() {
  clearInterval(watching);
  watching = null;
  $("watch-copy").textContent = "Watch next copy";
}
function clearPairResult() {
  clearInterval(pairTimer);
  pairTimer = null;
  pairGeneration += 1;
  $("pair-code").textContent = "";
  $("pair-command").textContent = "";
  $("pair-expiry").textContent = "";
  $("copy-pair").disabled = false;
  show("pair-result", false);
}
function setPairResult(data, origin) {
  clearPairResult();
  const generation = ++pairGeneration,
    expiresAt = Date.now() + data.expires_in * 1000;
  $("pair-code").textContent = data.code;
  $("pair-command").textContent = `latchlane pair ${origin} --name 'My agent'`;
  show("pair-result");
  const tick = () => {
    const remaining = (expiresAt - Date.now()) / 1000;
    if (generation !== pairGeneration) return;
    if (remaining <= 0) {
      clearInterval(pairTimer);
      pairTimer = null;
      $("pair-code").textContent = "Expired — generate a fresh pairing code.";
      $("pair-expiry").textContent = "Expired";
      $("copy-pair").disabled = true;
      return;
    }
    $("pair-expiry").textContent = `Expires in ${formatRemaining(remaining)}`;
  };
  tick();
  pairTimer = setInterval(tick, 1000);
}
function clearSensitiveUI() {
  stopWatch();
  clearPairResult();
  copiedValue = null;
  $("key-form").reset();
  $("key-value").value = "";
  $("password").value = "";
  $("confirm").value = "";
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  clearDialogNotices();
}
async function showLoggedOut(message) {
  clearSensitiveUI();
  renderedSignature = null;
  state = null;
  try {
    presentWelcome(await api("/api/status"));
  } catch (error) {
    presentConnectionFailure();
  }
  if (message) notice(message, true);
}
function presentConnectionFailure() {
  initialized = false;
  show("dashboard", false);
  show("welcome");
  show("lock", false);
  show("logout", false);
  show("retry");
  $("entry-title").textContent = "Latchlane isn’t reachable.";
  $("entry-description").textContent =
    "Check that this vault host is running, then retry the connection.";
  $("enter").disabled = true;
  show("confirm-wrap", false);
}
async function handleActionError(error) {
  if (sessionError(error)) {
    await showLoggedOut(
      "Your session ended or the vault was locked. Sign in again.",
    );
    return;
  }
  if (error instanceof ApiError && error.status === 0) {
    if ($("dashboard").classList.contains("hidden")) presentConnectionFailure();
    else show("retry");
    notice(error.message, true);
    return;
  }
  notice(error.message || "Something went wrong. Try again.", true);
}
async function boot() {
  try {
    if (setupToken.startsWith("owner=")) {
      setupToken = setupToken.slice(6);
      await api("/api/local-session", "POST");
      setupToken = "";
    }
    const status = await api("/api/status");
    initialized = status.initialized;
    try {
      await refresh();
      if (captureParams.has("capture")) {
        openKey();
        $("key-name").value = captureParams.get("capture");
        $("key-origin").value = captureParams.get("origin") || "";
        const header = captureParams.get("header");
        const prefix = captureParams.get("prefix");
        if (
          [...$("key-header").options].some((option) => option.value === header)
        )
          $("key-header").value = header;
        if (["", "Bearer ", "Basic "].includes(prefix))
          $("key-prefix").value = prefix;
      }
      return;
    } catch (error) {
      if (!sessionError(error)) throw error;
      presentWelcome(status);
    }
  } catch (error) {
    await handleActionError(error);
  }
}
function openKey() {
  clearDialogNotices();
  $("key-form").reset();
  editingKey = null;
  copiedValue = null;
  stopWatch();
  $("key-name").disabled = false;
  $("key-value").required = true;
  $("key-value").placeholder = "Paste directly here";
  $("key-dialog-title").textContent = captureMode
    ? `Add ${captureParams.get("capture") || "API key"}`
    : "Keep it out of chat.";
  $("key-dialog-description").textContent = captureMode
    ? "Confirm the name and destination, paste the key, then save it locally."
    : "Name the key and its API destination. Then paste it here.";
  $("save-key").innerHTML = captureMode
    ? "Encrypt & save"
    : "Encrypt & save <span>↗</span>";
  $("key-fields").classList.remove("hidden");
  $("capture-success").classList.add("hidden");
  document
    .querySelectorAll("#key-fields details")
    .forEach((details) => (details.open = false));
  if (captureMode) compactCaptureFields();
  $("capture-state").textContent =
    "Clipboard access stays on this device. Paste manually if your browser blocks access.";
  $("key-dialog").showModal();
}
function compactCaptureFields() {
  if ($("capture-advanced")) return;
  const advanced = document.createElement("details");
  advanced.id = "capture-advanced";
  advanced.className = "capture-advanced";
  advanced.append(
    node("summary", "Advanced authentication and trusted-read options"),
  );
  const fields = $("key-fields"),
    auth = fields.querySelector(".two-cols"),
    paths = fields.querySelector("details");
  fields.insertBefore(advanced, $("key-value").previousElementSibling);
  advanced.append(auth, paths);
}
function openEdit(key) {
  openKey();
  editingKey = key;
  $("key-name").value = key.name;
  $("key-name").disabled = true;
  $("key-origin").value = key.origin;
  $("key-header").value = key.header;
  $("key-prefix").value = key.prefix;
  $("safe-paths").value = (key.safe_paths || []).join("\n");
  $("key-value").required = false;
  $("key-value").placeholder = "Leave blank to keep the current value";
  $("key-dialog-title").textContent = `Edit ${key.name}`;
  $("key-dialog-description").textContent =
    "Update routing details. Leave the secret blank to keep it unchanged.";
  $("save-key").innerHTML = "Save changes";
}
function registerPwa() {
  const standalone =
    matchMedia("(display-mode: standalone)").matches || navigator.standalone;
  document.documentElement.dataset.displayMode = standalone
    ? "standalone"
    : "browser";
  if ("serviceWorker" in navigator && window.isSecureContext)
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
}

$("login-form").onsubmit = async (event) => {
  event.preventDefault();
  const passphrase = $("password").value;
  if (!initialized && passphrase !== $("confirm").value) {
    notice("Those passphrases don’t match.", true);
    return;
  }
  $("enter").disabled = true;
  try {
    await api(initialized ? "/api/login" : "/api/init", "POST", {
      password: passphrase,
      session_mode: document.querySelector("[name=session-mode]:checked").value,
    });
    $("password").value = $("confirm").value = "";
    setupToken = "";
    initialized = true;
    await boot();
  } catch (error) {
    await handleActionError(error);
  } finally {
    $("enter").disabled = false;
  }
};
$("lock").onclick = async () => {
  if ($("lock").disabled) return;
  $("lock").disabled = true;
  try {
    await api("/api/lock", "POST");
    await showLoggedOut("Vault locked. Sign in again.");
  } catch (error) {
    await handleActionError(error);
  } finally {
    $("lock").disabled = false;
  }
};
$("logout").onclick = async () => {
  try {
    await api("/api/logout", "POST");
    await showLoggedOut(
      "Signed out here. Paired agents and other signed-in owner sessions stay available until the vault is locked.",
    );
  } catch (error) {
    await handleActionError(error);
  }
};
$("retry").onclick = () => boot();
$("install-app").onclick = async () => {
  if (!deferredInstallPrompt) {
    clearDialogNotices();
    $("app-dialog").showModal();
    return;
  }
  deferredInstallPrompt.prompt();
  await deferredInstallPrompt.userChoice;
  deferredInstallPrompt = null;
};
$("app-help").onclick = () => {
  clearDialogNotices();
  $("app-dialog").showModal();
};
$("notifications").onclick = async () => {
  if (!("Notification" in window) || Notification.permission === "denied")
    return;
  if (notificationsEnabled) {
    notificationsEnabled = false;
    localStorage.removeItem("latchlane-notifications");
    $("notification-status").textContent =
      "Approval notifications are off on this device.";
    updateNotificationStatus();
    return;
  }
  const permission = await Notification.requestPermission();
  notificationsEnabled = permission === "granted";
  if (notificationsEnabled)
    localStorage.setItem("latchlane-notifications", "yes");
  else localStorage.removeItem("latchlane-notifications");
  updateNotificationStatus();
  if (notificationsEnabled)
    $("notification-status").textContent =
      "Enabled while this app stays open. Alerts show only a waiting-approval count.";
};
$("add").onclick = openKey;
document
  .querySelectorAll("[data-close]")
  .forEach(
    (button) => (button.onclick = () => $(button.dataset.close).close()),
  );
$("key-dialog").addEventListener("close", () => {
  stopWatch();
  $("key-value").value = "";
  copiedValue = null;
  clearDialogNotices();
});
$("capture-another").onclick = openKey;
$("capture-done").onclick = () => window.close();
$("key-header").onchange = () => {
  $("key-prefix").value =
    $("key-header").value === "Authorization" ? "Bearer " : "";
};
$("clipboard").onclick = async () => {
  try {
    copiedValue = await navigator.clipboard.readText();
    $("key-value").value = copiedValue;
    notice("Captured locally. Choose Encrypt & save.");
  } catch (error) {
    notice(
      "Clipboard access unavailable. Paste directly into the secret field.",
      true,
    );
  }
};
$("watch-copy").onclick = async () => {
  if (watching) {
    stopWatch();
    return;
  }
  try {
    const initial = await navigator.clipboard.readText();
    $("watch-copy").textContent = "Cancel watching";
    $("capture-state").textContent =
      "Copy your key, then return to this window. Waiting for a new value for 2 minutes.";
    const expires = Date.now() + 120000;
    let busy = false;
    watching = setInterval(async () => {
      if (Date.now() > expires) {
        stopWatch();
        $("capture-state").textContent =
          "No new copy received. You can try again.";
        return;
      }
      if (!document.hasFocus() || busy) return;
      busy = true;
      try {
        const value = await navigator.clipboard.readText();
        if (value && value !== initial) {
          copiedValue = value;
          $("key-value").value = value;
          stopWatch();
          if ($("key-form").reportValidity()) $("key-form").requestSubmit();
          else
            notice("Key captured. Complete the name and destination to save.");
        }
      } catch (error) {
        stopWatch();
        notice(
          "Browser stopped clipboard access. Paste into the secret field.",
          true,
        );
      } finally {
        busy = false;
      }
    }, 400);
  } catch (error) {
    notice(
      "This browser needs you to paste directly into the secret field.",
      true,
    );
  }
};
function clearExplicitlyCapturedClipboard(value) {
  let pendingValue = value;
  value = null;
  const releaseValue = () => {
    pendingValue = null;
  };
  const releaseTimer = setTimeout(releaseValue, 2000);
  navigator.clipboard
    .readText()
    .then((current) => {
      if (pendingValue && current === pendingValue)
        return navigator.clipboard.writeText("");
    })
    .catch(() => {})
    .finally(() => {
      clearTimeout(releaseTimer);
      releaseValue();
    });
}
$("key-form").onsubmit = async (event) => {
  event.preventDefault();
  stopWatch();
  const value = $("key-value").value,
    body = {
      name: $("key-name").value,
      origin: $("key-origin").value,
      header: $("key-header").value,
      prefix: $("key-prefix").value,
      safe_paths: $("safe-paths")
        .value.split("\n")
        .map((item) => item.trim())
        .filter(Boolean),
    },
    submit = $("save-key");
  if (!editingKey || value) body.value = value;
  if (submit.disabled) return;
  submit.disabled = true;
  try {
    await api(
      editingKey
        ? `/api/keys/${encodeURIComponent(editingKey.name)}`
        : "/api/keys",
      editingKey ? "PATCH" : "POST",
      body,
    );
    const shouldClearCapturedValue = copiedValue === value;
    $("key-value").value = "";
    copiedValue = null;
    if (captureMode && !editingKey) {
      $("key-fields").classList.add("hidden");
      $("capture-success").classList.remove("hidden");
    } else {
      $("key-dialog").close();
      notice("Encrypted and saved.");
    }
    if (shouldClearCapturedValue) clearExplicitlyCapturedClipboard(value);
    await refresh();
  } catch (error) {
    await handleActionError(error);
  } finally {
    submit.disabled = false;
  }
};
const descriptions = {
  ask: "Every key use waits for your approval. Approved requests can be used once and expire after five minutes.",
  auto: "Only exact GET routes you mark as trusted are approved automatically. Everything else, including raw-key access, asks you first. GET alone is not a safety guarantee.",
  yolo: "Every paired agent can use every stored key without asking, including raw-key access. A paired agent may retain or share released keys. Only enable this for agents and devices you trust.",
};
document.querySelectorAll("[data-mode]").forEach(
  (mode) =>
    (mode.onclick = () => {
      chosenMode = mode.dataset.mode;
      if (chosenMode === currentMode) return;
      clearDialogNotices();
      $("mode-title").textContent =
        `Switch to ${mode.querySelector("strong").textContent}?`;
      $("mode-description").textContent =
        `${descriptions[chosenMode]} Changing mode cancels pending approvals.`;
      $("mode-dialog").showModal();
    }),
);
$("confirm-mode").onclick = async () => {
  if ($("confirm-mode").disabled) return;
  $("confirm-mode").disabled = true;
  try {
    await api("/api/mode", "POST", { mode: chosenMode });
    $("mode-dialog").close();
    await refresh();
    notice("Your access mode is updated.");
  } catch (error) {
    await handleActionError(error);
  } finally {
    $("confirm-mode").disabled = false;
  }
};
$("pair").onclick = async () => {
  if ($("pair").disabled) return;
  $("pair").disabled = true;
  try {
    const origin = new URL(location.href).origin;
    if (!/^https?:$/.test(new URL(origin).protocol))
      throw new Error("This console address is not a valid pairing origin.");
    setPairResult(await api("/api/invite", "POST"), origin);
  } catch (error) {
    await handleActionError(error);
  } finally {
    $("pair").disabled = false;
  }
};
async function copyText(value, label) {
  try {
    await navigator.clipboard.writeText(value);
    notice(`${label} copied.`);
  } catch (error) {
    notice(`Select and copy the ${label.toLowerCase()} manually.`, true);
  }
}
$("copy-pair").onclick = () =>
  copyText($("pair-code").textContent, "Pairing code");
$("copy-pair-command").onclick = () =>
  copyText($("pair-command").textContent, "Pairing command");
$("sync-guide").onclick = () => {
  clearDialogNotices();
  $("sync-dialog").showModal();
};
$("mcp-guide").onclick = () => {
  clearDialogNotices();
  $("mcp-dialog").showModal();
};
window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  deferredInstallPrompt = event;
});
window.addEventListener("appinstalled", () => {
  deferredInstallPrompt = null;
  $("install-app").textContent = "Latchlane app installed";
  $("install-app").disabled = true;
});
window.addEventListener("pagehide", () => {
  stopWatch();
  copiedValue = null;
  $("key-value").value = "";
  $("password").value = "";
  $("confirm").value = "";
});
updateNotificationStatus();
registerPwa();
boot();
setInterval(async () => {
  if (
    $("dashboard").classList.contains("hidden") ||
    document.visibilityState !== "visible"
  )
    return;
  try {
    await refresh();
  } catch (error) {
    if (sessionError(error))
      await showLoggedOut(
        "Your session ended or the vault was locked. Sign in again.",
      );
    else await handleActionError(error);
  }
}, 4000);
