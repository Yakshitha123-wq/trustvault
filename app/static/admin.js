"use strict";

const form = document.getElementById("filters");
const rows = document.getElementById("rows");
const statusBox = document.getElementById("statusBox");
const olderButton = document.getElementById("older");
const verifyButton = document.getElementById("verify");
const verifyBox = document.getElementById("verifyBox");
const FIELDS = ["document_id", "actor_id", "action", "outcome", "from", "to", "limit"];
let nextBefore = null;

function query(extra) {
  const params = new URLSearchParams();
  for (const name of FIELDS) {
    const value = document.getElementById("f-" + name).value.trim();
    if (value !== "") params.set(name, value);
  }
  for (const [key, value] of Object.entries(extra || {})) params.set(key, value);
  return params.toString();
}

function eventRow(e) {
  return el("tr", {},
    el("td", { text: String(e.id) }),
    el("td", { text: formatDate(e.ts) }),
    el("td", { text: e.actor_name || (e.actor_id ? "(removed user)" : "anonymous") }),
    el("td", { text: e.action }),
    el("td", {}, el("span", { class: "badge " + (e.outcome === "denied" ? "denied" : "allowed"), text: e.outcome })),
    el("td", {}, e.document_id
      ? el("a", { href: "/app/documents/" + encodeURIComponent(e.document_id), text: e.document_id.slice(0, 8) })
      : null),
    el("td", { text: e.target_name || "" }),
    el("td", { text: e.ip || "" }),
    el("td", {}, el("code", { text: JSON.stringify(e.detail) })));
}

async function load(older) {
  const extra = older && nextBefore ? { before_id: String(nextBefore) } : {};
  const result = await api("/admin/activity?" + query(extra));
  if (!older) rows.replaceChildren();
  if (!result.ok) {
    setStatus(statusBox, errorText(result, "Could not load the activity."), "error");
    olderButton.hidden = true;
    return;
  }
  for (const e of result.data.events) rows.append(eventRow(e));
  nextBefore = result.data.next_before_id;
  olderButton.hidden = nextBefore === null;
  setStatus(statusBox, rows.children.length ? "" : "No events match.", "info");
}

form.addEventListener("submit", (e) => { e.preventDefault(); nextBefore = null; load(false); });
form.addEventListener("reset", () => setTimeout(() => { nextBefore = null; load(false); }, 0));
olderButton.addEventListener("click", () => load(true));

document.querySelectorAll("button[data-set]").forEach((button) => {
  button.addEventListener("click", () => {
    form.reset();
    const [name, value] = button.dataset.set.split("=");
    document.getElementById("f-" + name).value = value;
    nextBefore = null;
    load(false);
  });
});

verifyButton.addEventListener("click", async () => {
  setStatus(verifyBox, "Checking...", "info");
  const result = await api("/admin/audit/verify");
  if (!result.ok) {
    setStatus(verifyBox, errorText(result, "Could not verify."), "error");
    return;
  }
  if (result.data.intact) setStatus(verifyBox, "Audit chain intact: every row verified.", "ok");
  else setStatus(verifyBox, "AUDIT CHAIN BROKEN at row " + result.data.first_bad_row + ".", "error");
  load(false);  // the check is itself audited, so refresh to show it
});

load(false);