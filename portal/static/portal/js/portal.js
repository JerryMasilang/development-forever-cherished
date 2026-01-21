(function () {
  const btnReserve = document.getElementById("btnReserve");
  const btnAssign = document.getElementById("btnAssign");
  const checkAll = document.getElementById("checkAll");

  function getAllCheckboxes() {
    return document.querySelectorAll(".qr-check");
  }

  function getSelectedCheckboxes() {
    return Array.from(getAllCheckboxes()).filter(cb => cb.checked);
  }

  function getSelectedStatuses() {
    return getSelectedCheckboxes()
      .map(cb => cb.closest("[data-status]")?.getAttribute("data-status"))
      .filter(Boolean);
  }

  function updateButtons() {
    const statuses = getSelectedStatuses();
    const unique = [...new Set(statuses)];
    const anySelected = statuses.length > 0;

    // Default: disabled
    if (btnReserve) btnReserve.disabled = true;
    if (btnAssign) btnAssign.disabled = true;

    // Must not allow mixed-status selections
    if (!anySelected || unique.length !== 1) return;

    const status = unique[0];
    if (btnReserve) btnReserve.disabled = (status !== "AVAILABLE");
    if (btnAssign) btnAssign.disabled = (status !== "RESERVED");
  }

  // Handle checkAll for desktop table
  if (checkAll) {
    checkAll.addEventListener("change", () => {
      getAllCheckboxes().forEach(cb => {
        cb.checked = checkAll.checked;
      });
      updateButtons();
    });
  }

  // Handle individual checkbox changes
  getAllCheckboxes().forEach(cb => cb.addEventListener("change", updateButtons));

  // Initial state
  updateButtons();
})();

// Copy-to-clipboard helper (for Copy URL actions)
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".copy-btn");
  if (!btn) return;

  const text = btn.getAttribute("data-copy");
  if (!text) return;

  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied!";
    const original = btn.dataset.originalText || btn.textContent;
    btn.dataset.originalText = original;
    setTimeout(() => (btn.textContent = original), 900);

  } catch (err) {
    alert("Copy failed. Please copy manually.");
  }
});

// View QR modal population
document.addEventListener("click", (e) => {
  const btn = e.target.closest(".view-qr-btn");
  if (!btn) return;

  const qrId = btn.getAttribute("data-qr-id") || "—";
  const qrUrl = btn.getAttribute("data-qr-url") || "";

  const elId = document.getElementById("qrModalId");
  const elUrl = document.getElementById("qrModalUrl");
  const elImg = document.getElementById("qrModalImg");
  const elCopy = document.getElementById("qrModalCopyBtn");
  const elOpen = document.getElementById("qrModalOpenBtn");

  if (elId) elId.textContent = qrId;
  if (elUrl) elUrl.textContent = qrUrl;
  if (elCopy) elCopy.setAttribute("data-copy", qrUrl);
  if (elOpen) elOpen.setAttribute("href", qrUrl);

  // Temporary QR image generator (dev mode)
  const qrImgUrl = "/portal/qr/png/" + encodeURIComponent(qrId) + "/";

  if (elImg) elImg.setAttribute("src", qrImgUrl);
});
