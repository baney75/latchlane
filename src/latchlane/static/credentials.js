/* Private owner forms. No secret is put in storage, a URL, or model-facing output. */
"use strict";
window.LatchlaneCredentials = (() => {
  const MAX_FILE = 1024 * 1024;
  const MAX_ROWS = 200;
  const MAX_BATCH = 20;
  const aliases = {
    name: ["title", "name", "itemname", "servicename"],
    origin: ["loginuri", "url", "website", "websiteurl", "origin", "loginurl"],
    username: ["loginusername", "username", "email", "login", "account"],
    value: ["loginpassword", "password", "apikey", "secret", "token"],
  };
  const normalize = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  function parseCsv(text) {
    text = text.replace(/^\uFEFF/, "");
    const rows = [];
    let row = [], field = "", quoted = false, closed = false;
    function cell() {
      if (field.length > 65536 || row.length >= 100) throw Error("This CSV has an oversized field or too many columns.");
      row.push(field); field = ""; closed = false;
    }
    function line() {
      cell();
      if (row.some((v) => v.length)) rows.push(row);
      row = [];
      if (rows.length > MAX_ROWS + 1) throw Error("Choose an export with at most 200 entries, then import up to 20 at a time.");
    }
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) {
        if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
        else if (c === '"') { quoted = false; closed = true; }
        else field += c;
      } else if (c === ",") cell();
      else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; line(); }
      else if (closed && /[ \t]/.test(c)) continue;
      else if (closed) throw Error("The CSV has unexpected text after a quoted field.");
      else if (c === '"' && field === "") quoted = true;
      else if (c === '"') throw Error("The CSV contains an unescaped quote. Export it again as CSV.");
      else field += c;
    }
    if (quoted) throw Error("The CSV contains an unfinished quoted field.");
    if (field || row.length || closed) line();
    if (rows.length < 2) throw Error("Choose a CSV with a header row and at least one entry.");
    if (rows.some((r) => r.length !== rows[0].length)) throw Error("CSV rows have different column counts. Check the export format.");
    return rows;
  }
  function originFrom(value) {
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) return "";
      return url.origin;
    } catch { return ""; }
  }
  function mount({ api, refresh, onError, notice }) {
    const $ = (id) => document.getElementById(id);
    const el = (tag, text, cls) => {
      const n = document.createElement(tag);
      if (text !== undefined) n.textContent = text;
      if (cls) n.className = cls;
      return n;
    };
    let rawRows = [], entries = [], collection = null, collectionRows = [];
    let existingNames = new Set(), generation = 0, collectionGeneration = 0;
    let collectionSignature = "", deepLinkOpened = false;
    function input(label, id, value = "", type = "text") {
      const wrap = el("div"), caption = el("label", label), field = el("input");
      caption.htmlFor = id; field.id = id; field.type = type; field.value = value;
      field.autocomplete = "off";
      wrap.append(caption, field);
      return { wrap, field };
    }
    function eraseEntries() {
      for (const entry of entries) entry.value = "";
      entries = [];
      $("import-entries").replaceChildren();
    }
    function clearImport() {
      generation++;
      for (const row of rawRows) row.fill("");
      rawRows = []; eraseEntries();
      $("import-file").value = "";
      $("import-map-fields").replaceChildren();
      $("import-mapping").classList.add("hidden");
      $("import-review-panel").classList.add("hidden");
      $("import-save").disabled = true;
      $("import-save").textContent = "Choose entries to import";
    }
    function clearCollection() {
      collectionGeneration++;
      for (const row of collectionRows) { row.value.value = ""; row.username.value = ""; }
      collectionRows = []; collection = null;
      $("collection-fields").replaceChildren();
    }
    function reset() {
      clearImport(); clearCollection();
      $("collections-list").replaceChildren();
      $("collections-panel").classList.add("hidden");
      collectionSignature = "";
    }
    $("import-dialog").addEventListener("close", clearImport);
    $("collection-dialog").addEventListener("close", clearCollection);
    window.addEventListener("pagehide", reset);
    $("import-credentials").onclick = () => {
      clearImport(); $("import-dialog").showModal();
    };
    function selectionChanged() {
      const n = entries.filter((e) => e.selected.checked).length;
      $("import-save").disabled = n === 0 || n > MAX_BATCH;
      $("import-save").textContent = n ? `Encrypt & save ${n} credential${n === 1 ? "" : "s"}` : "Choose entries to import";
      $("import-summary").textContent = `${entries.length} entries · ${n} selected`;
    }
    $("import-file").onchange = async () => {
      const file = $("import-file").files[0];
      clearImport();
      if (!file) return;
      const current = generation;
      if (file.size > MAX_FILE) { notice("Choose a CSV file no larger than 1 MiB.", true); return; }
      let text = "";
      try {
        text = await file.text();
        if (generation !== current || !$("import-dialog").open) return;
        rawRows = parseCsv(text); text = "";
        const headers = rawRows[0].map(normalize);
        for (const [key, names] of Object.entries(aliases)) {
          const wrap = el("div"), label = el("label", { name: "Name / title", origin: "Website / URL", username: "Username (optional)", value: "Password / secret" }[key]);
          const select = el("select"); select.id = `map-${key}`; label.htmlFor = select.id;
          const empty = el("option", key === "name" ? "Generate names" : key === "username" ? "No username" : "Choose a column");
          empty.value = "-1"; select.append(empty);
          headers.forEach((header, i) => {
            const known = Object.values(aliases).some((a) => a.includes(header));
            const option = el("option", `Column ${i + 1}${known ? ` · ${header}` : ""}`);
            option.value = String(i); select.append(option);
          });
          select.value = String(headers.findIndex((h) => names.includes(h)));
          wrap.append(label, select); $("import-map-fields").append(wrap);
        }
        $("import-mapping").classList.remove("hidden");
      } catch (error) { if (current === generation) { clearImport(); notice(error.message || "Could not read this CSV.", true); } }
      finally { text = ""; }
    };
    $("import-review").onclick = () => {
      eraseEntries();
      try {
        const mapping = Object.fromEntries(Object.keys(aliases).map((key) => [key, Number($(`map-${key}`).value)]));
        if (mapping.value < 0 || mapping.origin < 0) throw Error("Choose the password and website columns first.");
        if (new Set(Object.values(mapping).filter((n) => n >= 0)).size !== Object.values(mapping).filter((n) => n >= 0).length)
          throw Error("Use a different column for each field.");
        const usedNames = new Set(existingNames);
        rawRows.slice(1).forEach((row, index) => {
          const value = row[mapping.value];
          if (!value) return;
          const title = mapping.name >= 0 ? row[mapping.name] : "";
          const base = title.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^[-_]+|[-_]+$/g, "").slice(0, 52) || `credential-${index + 1}`;
          let name = base, suffix = 2;
          while (usedNames.has(name)) name = `${base}-${suffix++}`;
          usedNames.add(name);
          const card = el("fieldset", undefined, "credential-card");
          const legend = el("legend", `Entry ${index + 1}`); card.append(legend);
          const checkLabel = el("label", undefined, "import-selection"), selected = el("input");
          selected.type = "checkbox"; selected.setAttribute("aria-label", `Import entry ${index + 1}`);
          checkLabel.append(selected, document.createTextNode("Import this entry")); card.append(checkLabel);
          const nameField = input("Name in Latchlane", `import-name-${index}`, name);
          nameField.field.pattern = "[a-z0-9][a-z0-9_-]{0,63}"; nameField.field.maxLength = 64;
          const origin = input("HTTPS website / API origin", `import-origin-${index}`, originFrom(row[mapping.origin]), "url");
          const username = input("Username or email", `import-username-${index}`, mapping.username >= 0 ? row[mapping.username] : "");
          username.field.maxLength = 320;
          const kindWrap = el("div"), kindLabel = el("label", "Credential type"), kind = el("select");
          kind.id = `import-kind-${index}`; kindLabel.htmlFor = kind.id;
          for (const [v, label] of [["password", "Login password"], ["api_key", "API key (Authorization: Bearer)"]]) { const o = el("option", label); o.value = v; kind.append(o); }
          kindWrap.append(kindLabel, kind);
          card.append(nameField.wrap, origin.wrap, kindWrap, username.wrap, el("p", "Secret value ready · hidden", "fine"));
          if (!origin.field.value) card.append(el("p", "This entry needs a valid HTTPS website before you select it.", "fine"));
          const entry = { value, selected, name: nameField.field, origin: origin.field, username: username.field, kind };
          entries.push(entry);
          selected.onchange = () => {
            if (selected.checked && entries.filter((e) => e.selected.checked).length > MAX_BATCH) { selected.checked = false; notice("Import up to 20 entries per batch.", true); }
            selectionChanged();
          };
          kind.onchange = () => { username.wrap.classList.toggle("hidden", kind.value !== "password"); };
          $("import-entries").append(card);
        });
        if (!entries.length) throw Error("No entries have a value in that column. Choose the password or secret column.");
        $("import-review-panel").classList.remove("hidden"); selectionChanged();
        $("import-review-panel").scrollIntoView({ block: "start" });
      } catch (error) { eraseEntries(); notice(error.message, true); }
    };
    $("import-select-all").onclick = () => { entries.forEach((e, i) => { e.selected.checked = i < MAX_BATCH; }); selectionChanged(); };
    $("import-select-none").onclick = () => { entries.forEach((e) => { e.selected.checked = false; }); selectionChanged(); };
    $("import-form").onsubmit = async (event) => {
      event.preventDefault();
      if ($("import-save").disabled) return;
      let items = [];
      const current = generation;
      try {
        const chosen = entries.filter((e) => e.selected.checked);
        if (!chosen.length || chosen.length > MAX_BATCH) throw Error("Select between 1 and 20 entries.");
        items = chosen.map((e) => {
          if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(e.name.value)) throw Error("Use a short lowercase name with letters, digits, dashes, or underscores.");
          const origin = originFrom(e.origin.value);
          if (!origin || e.origin.value.replace(/\/$/, "") !== origin) throw Error("Use an HTTPS origin without a path, such as https://example.com.");
          if (existingNames.has(e.name.value)) throw Error("A selected name already exists. Choose a new name; imports never overwrite credentials.");
          return { name: e.name.value, value: e.value, kind: e.kind.value, username: e.kind.value === "password" ? e.username.value : "", origin, header: "Authorization", prefix: e.kind.value === "password" ? "" : "Bearer ", safe_paths: [] };
        });
        if (new Set(items.map((i) => i.name)).size !== items.length) throw Error("Give each selected entry a different name.");
        if (new TextEncoder().encode(JSON.stringify({ items })).length > 95000) throw Error("These entries are too large for one batch. Select fewer entries.");
        $("import-save").disabled = true;
        await api("/api/keys/batch", "POST", { items });
        if (current !== generation) return;
        $("import-dialog").close(); notice("Selected credentials encrypted and saved. Your access mode is unchanged.");
        await refresh();
      } catch (error) { if (current === generation) { selectionChanged(); await onError(error); } }
      finally { items.forEach((item) => { item.value = ""; item.username = ""; }); items = []; }
    };
    async function openCollection(id) {
      if (!/^[A-Za-z0-9_-]{20,40}$/.test(id)) { notice("This credential request link is invalid.", true); return; }
      clearCollection();
      const current = collectionGeneration;
      try {
        const data = await api(`/api/owner/collections/${id}`);
        if (current !== collectionGeneration) return;
        collection = data;
        $("collection-title").textContent = `${data.agent} needs ${data.items.length} credential${data.items.length === 1 ? "" : "s"}`;
        $("collection-purpose").textContent = data.purpose;
        $("collection-expiry").textContent = `Request expires at ${new Date(data.expires_at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`;
        data.items.forEach((item, i) => {
          const card = el("fieldset", undefined, "credential-card");
          card.append(el("legend", item.name), el("p", `${item.kind === "password" ? "Login password" : "API key"} · ${item.origin}`, "credential-destination"));
          if (item.kind !== "password") card.append(el("p", `${item.header}${item.prefix ? ` · ${item.prefix.trim()}` : " · no prefix"}`, "fine"));
          const username = input("Username or email", `collection-user-${i}`);
          username.field.name = `username-${i}`; username.field.autocomplete = `section-credential${i} username`; username.field.maxLength = 320;
          if (item.kind !== "password") username.wrap.classList.add("hidden");
          const value = input(item.kind === "password" ? "Password" : "API key", `collection-secret-${i}`, "", "password");
          value.field.name = `password-${i}`; value.field.autocomplete = item.kind === "password" ? `section-credential${i} current-password` : "off";
          value.field.required = true; value.field.maxLength = 16384; value.field.spellcheck = false;
          card.append(username.wrap, value.wrap); $("collection-fields").append(card);
          collectionRows.push({ item, username: username.field, value: value.field });
        });
        $("collection-save").disabled = false; $("collection-cancel").disabled = false;
        $("collection-dialog").showModal();
      } catch (error) { if (current === collectionGeneration) { clearCollection(); await onError(error); } }
    }
    $("collection-form").onsubmit = async (event) => {
      event.preventDefault();
      if (!collection || $("collection-save").disabled) return;
      const current = collectionGeneration;
      let items = collectionRows.map((r) => ({ name: r.item.name, kind: r.item.kind, origin: r.item.origin, header: r.item.header, prefix: r.item.prefix, username: r.item.kind === "password" ? r.username.value : "", value: r.value.value }));
      $("collection-save").disabled = true;
      try {
        await api(`/api/owner/collections/${collection.id}/complete`, "POST", { items });
        if (current !== collectionGeneration) return;
        $("collection-dialog").close();
        const url = new URL(location.href); url.searchParams.delete("collection"); history.replaceState(null, "", url.pathname + url.search);
        notice("Saved. Your agent can continue; key-use permissions still apply."); await refresh();
      } catch (error) { if (current === collectionGeneration) { $("collection-save").disabled = false; await onError(error); } }
      finally { items.forEach((i) => { i.value = ""; i.username = ""; }); items = []; }
    };
    $("collection-cancel").onclick = async () => {
      if (!collection || $("collection-cancel").disabled) return;
      const current = collectionGeneration, id = collection.id;
      $("collection-cancel").disabled = true;
      try {
        await api(`/api/owner/collections/${id}/cancel`, "POST", {});
        if (current !== collectionGeneration) return;
        $("collection-dialog").close(); notice("Request declined."); await refresh();
      } catch (error) {
        if (current === collectionGeneration) { $("collection-cancel").disabled = false; await onError(error); }
      }
    };
    function update(next) {
      existingNames = new Set(next.keys.map((k) => k.name));
      const requests = next.collections || [];
      const signature = JSON.stringify(requests);
      if (signature === collectionSignature) return;
      collectionSignature = signature;
      $("collections-panel").classList.toggle("hidden", requests.length === 0);
      $("collections-list").replaceChildren();
      for (const request of requests) {
        const card = el("article", undefined, "request"), open = el("button", "Fill privately", "primary");
        card.append(el("h3", `${request.agent} needs ${request.items.length} credential${request.items.length === 1 ? "" : "s"}`), el("p", request.purpose));
        open.type = "button"; open.onclick = () => openCollection(request.id); card.append(open);
        $("collections-list").append(card);
      }
      if (collection && !requests.some((r) => r.id === collection.id)) {
        $("collection-dialog").close(); notice("This credential request ended. Unsaved values were cleared.", true);
      }
    }
    async function openDeepLink() {
      const id = new URLSearchParams(location.search).get("collection");
      if (id && !deepLinkOpened) { deepLinkOpened = true; await openCollection(id); }
    }
    return { reset, update, openDeepLink };
  }
  return { mount };
})();
