"use strict";

const form = document.getElementById("filters");
const rows = document.getElementById("rows");
const statusBox = document.getElementById("statusBox");

async function load() {
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form)) {
    if (value.trim() !== "") params.set(key, value.trim());
  }
  const result = await api("/documents?" + params.toString());
  rows.replaceChildren();
  if (!result.ok) {
    setStatus(statusBox, errorText(result, "Could not load documents."), "error");
    return;
  }
  const docs = result.data.documents;
  setStatus(statusBox, docs.length ? "" : "No documents match.", "info");
  for (const d of docs) {
    rows.append(el("tr", {},
      el("td", {}, el("a", { href: "/app/documents/" + encodeURIComponent(d.id), text: d.name })),
      el("td", { text: d.category }),
      el("td", { text: d.owner_name }),
      el("td", { text: formatSize(d.size_bytes) }),
      el("td", { text: formatDate(d.created_at) }),
      el("td", {}, el("span", { class: "badge " + (d.my_permission === "owner" ? "owner" : ""), text: d.my_permission }))));
  }
}

form.addEventListener("submit", (e) => { e.preventDefault(); load(); });
form.addEventListener("reset", () => setTimeout(load, 0));
load();