"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// Build DOM nodes without ever parsing HTML: strings become text nodes.
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (value != null && value !== false) node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child != null) node.append(child);
  }
  return node;
}

async function api(path, options = {}) {
  const method = options.method || "GET";
  const init = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") {
    init.headers["X-CSRFToken"] = csrfToken;
    if (options.form) init.body = new URLSearchParams(options.form);
    if (options.body) init.body = options.body;  // FormData: the browser sets the boundary
  }
  const response = await fetch(path, init);
  if (response.status === 401) {
    window.location.href = "/login";
    return { ok: false, status: 401, data: null };
  }
  let data = null;
  try { data = await response.json(); } catch (e) { /* not JSON, for example an HTML error page */ }
  return { ok: response.ok, status: response.status, data };
}

function setStatus(node, message, kind) {
  node.textContent = message;
  node.className = "msg " + kind;
  node.hidden = !message;
}

function errorText(result, fallback) {
  if (result.data && result.data.error) return result.data.error;
  if (result.status === 403) return "You are not allowed to do that.";
  if (result.status === 404) return "Not found.";
  if (result.status === 413) return "The file is too large (limit 5 MB).";
  if (result.status === 400) return "The request was rejected. If this page has been open for a while, reload it and try again.";
  if (result.status === 429) return "Too many attempts. Wait a minute and try again.";
  return fallback;
}

function formatSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

function formatDate(iso) {
  return new Date(iso).toLocaleString();
}