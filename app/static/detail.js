"use strict";

const root = document.getElementById("detail");
const base = "/documents/" + encodeURIComponent(root.dataset.docId);
const statusBox = document.getElementById("statusBox");
const title = document.getElementById("title");
const facts = document.getElementById("facts");
const actions = document.getElementById("actions");
const editSection = document.getElementById("edit-section");
const shareSection = document.getElementById("share-section");
const deleteSection = document.getElementById("delete-section");
const shareStatus = document.getElementById("shareStatus");
const grantsBody = document.getElementById("grants");

function fact(label, value) {
  facts.append(el("dt", { text: label }), el("dd", { text: value }));
}

async function load() {
  const result = await api(base);
  if (!result.ok) {
    setStatus(statusBox, result.status === 404 ? "Document not found." : errorText(result, "Could not load the document."), "error");
    return;
  }
  const d = result.data;
  title.textContent = d.name;
  facts.replaceChildren();
  fact("Category", d.category);
  fact("Type", d.mime_type);
  fact("Size", formatSize(d.size_bytes));
  fact("Uploaded", formatDate(d.created_at));

  actions.replaceChildren();
  if (d.can.read) {
    actions.append(el("a", { class: "button", href: base + "/download", text: "Download" }));
  } else {
    actions.append(el("span", { class: "msg info", text: "You can see this document's details but not its contents." }));
  }

  // The buttons only mirror authorize(); the server checks again on every request.
  editSection.hidden = !d.can.edit;
  shareSection.hidden = !d.can.share;
  deleteSection.hidden = !d.can.delete;
  document.getElementById("edit-name").value = d.name;
  document.getElementById("edit-category").value = d.category;
  if (d.can.share) loadGrants();
}

async function loadGrants() {
  const result = await api(base + "/grants");
  grantsBody.replaceChildren();
  if (!result.ok) {
    setStatus(shareStatus, errorText(result, "Could not load who has access."), "error");
    return;
  }
  const grants = result.data.grants;
  if (!grants.length) {
    grantsBody.append(el("tr", {}, el("td", { colspan: "4", text: "Not shared with anyone yet." })));
  }
  for (const g of grants) {
    grantsBody.append(el("tr", {},
      el("td", { text: g.email }),
      el("td", { text: g.name }),
      el("td", {}, el("span", { class: "badge", text: g.permission })),
      el("td", {}, el("button", { class: "secondary", type: "button", text: "Revoke", "data-user": g.user_id }))));
  }
}

document.getElementById("edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = { name: document.getElementById("edit-name").value.trim() };
  const category = document.getElementById("edit-category").value.trim();
  if (category) form.category = category;
  const result = await api(base + "/edit", { method: "POST", form });
  if (result.ok) {
    setStatus(statusBox, "Saved.", "ok");
    load();
  } else {
    setStatus(statusBox, errorText(result, "Could not save."), "error");
  }
});

document.getElementById("grant-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = {
    email: document.getElementById("grant-email").value.trim(),
    permission: document.getElementById("grant-permission").value,
  };
  const result = await api(base + "/grants", { method: "POST", form });
  if (result.ok) {
    setStatus(shareStatus, "Access given. It works on their next request.", "ok");
    e.target.reset();
    loadGrants();
  } else {
    setStatus(shareStatus, errorText(result, "Could not give access."), "error");
  }
});

grantsBody.addEventListener("click", async (e) => {
  const button = e.target.closest("button[data-user]");
  if (!button) return;
  const result = await api(base + "/grants/" + encodeURIComponent(button.dataset.user) + "/revoke", { method: "POST" });
  if (result.ok) {
    setStatus(shareStatus, "Access removed. It stopped working immediately.", "ok");
    loadGrants();
  } else {
    setStatus(shareStatus, errorText(result, "Could not remove access."), "error");
  }
});

document.getElementById("delete-btn").addEventListener("click", async () => {
  if (!window.confirm("Delete this document? Everyone else loses access immediately.")) return;
  const result = await api(base + "/delete", { method: "POST" });
  if (result.ok) window.location.href = "/app";
  else setStatus(statusBox, errorText(result, "Could not delete."), "error");
});

load();