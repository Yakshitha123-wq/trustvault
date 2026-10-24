"use strict";

const form = document.getElementById("upload");
const statusBox = document.getElementById("statusBox");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  setStatus(statusBox, "Uploading...", "info");
  const result = await api("/documents", { method: "POST", body: new FormData(form) });
  if (result.status === 201) {
    window.location.href = "/app/documents/" + encodeURIComponent(result.data.id);
    return;
  }
  setStatus(statusBox, errorText(result, "The upload failed."), "error");
});