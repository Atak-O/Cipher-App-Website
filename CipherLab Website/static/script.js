const cipherProfiles = {
  caesar: { fields: ["shift"], alphabet: true, hint: "Shift moves forward; Back moves backward. Net movement is Shift minus Back." },
  vigenere: { fields: ["key"], alphabet: true, hint: "Vigenère requires a repeating text key." },
  atbash: { fields: [], alphabet: true, hint: "Atbash uses alphabet reversal, so encrypt and decrypt are identical." },
  rot13: { fields: [], alphabet: false, hint: "ROT13 is a fixed English Caesar shift of 13." },
  morse: { fields: [], alphabet: false, hint: "Use spaces between Morse letters and / between words when decrypting." },
  base64: { fields: [], alphabet: false, hint: "Base64 is encoding, not cryptographic encryption." },
  binary: { fields: [], alphabet: false, hint: "Binary decrypt expects 8-bit blocks separated by optional spaces." },
  xor: { fields: ["key"], alphabet: false, hint: "XOR requires the same key for encryption and decryption." },
  rail_fence: { fields: ["rails"], alphabet: false, hint: "Rail Fence uses a zigzag transposition. Rails must be 2 or higher." },
  affine: { fields: ["affine"], alphabet: true, hint: "Affine requires a and b values. For English, a=5 and b=8 is common." },
};

const state = {
  result: "",
  history: [],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const elements = {
  cipherForm: $("#cipherForm"),
  cipherType: $("#cipherType"),
  alphabetGroup: $("#alphabetGroup"),
  alphabet: $("#alphabet"),
  inputText: $("#inputText"),
  charCount: $("#charCount"),
  fieldHint: $("#fieldHint"),
  result: $("#cipherResult"),
  resultStatus: $("#resultStatus"),
  copyResult: $("#copyResult"),
  downloadResult: $("#downloadResult"),
  assistantForm: $("#assistantForm"),
  assistantInput: $("#assistantInput"),
  assistantCount: $("#assistantCount"),
  analysisPanel: $("#analysisPanel"),
  historyList: $("#historyList"),
  saveHistory: $("#saveHistory"),
  loader: $("#loader"),
  toastStack: $("#toastStack"),
  navToggle: $(".nav-toggle"),
  navLinks: $(".nav-links"),
};

function setLoading(isLoading) {
  elements.loader.classList.toggle("hidden", !isLoading);
}

function toast(message, type = "success") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.textContent = message;
  elements.toastStack.appendChild(item);
  window.setTimeout(() => item.remove(), 3200);
}

function updateCipherFields() {
  const profile = cipherProfiles[elements.cipherType.value];
  $$(".param-field").forEach((field) => {
    field.classList.toggle("hidden", !profile.fields.includes(field.dataset.param));
  });
  elements.alphabetGroup.classList.toggle("hidden", !profile.alphabet);
  elements.fieldHint.textContent = profile.hint;
}

function updateCounters() {
  elements.charCount.textContent = `${elements.inputText.value.length} characters`;
  elements.assistantCount.textContent = `${elements.assistantInput.value.length} characters`;
}

function collectParams() {
  return {
    alphabet: elements.alphabet.value,
    shift: $("#shift").value,
    back: $("#back").value,
    key: $("#key").value,
    rails: $("#rails").value,
    a: $("#affineA").value,
    b: $("#affineB").value,
  };
}

async function requestJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error || "Request failed.");
  }
  return payload;
}

function renderHistory(history = []) {
  if (!history.length) {
    elements.historyList.innerHTML = '<p class="muted">No operations yet.</p>';
    return;
  }

  elements.historyList.innerHTML = history.map((item) => `
    <article class="history-item">
      <div>
        <code>${item.cipher}</code>
        <p>${item.mode} · ${item.timestamp}</p>
      </div>
      <p>${escapeHtml(item.result)}</p>
    </article>
  `).join("");
}

function addHistoryItem(item) {
  state.history.unshift(item);
  state.history = state.history.slice(0, 12);
  renderHistory(state.history);
}

function historyToText(history) {
  return history.map((item, index) => [
    `#${index + 1}`,
    `Time: ${item.timestamp}`,
    `Cipher: ${item.cipher}`,
    `Mode: ${item.mode}`,
    `Input: ${item.input}`,
    `Result: ${item.result}`,
  ].join("\n")).join("\n\n---\n\n");
}

function renderAnalysis(payload) {
  if (!payload.best) {
    elements.analysisPanel.innerHTML = `
      <div class="empty-state">
        <span class="pulse-dot"></span>
        <p>No strong match found. Try a longer sample for better frequency analysis.</p>
      </div>
    `;
    return;
  }

  const best = payload.best;
  const alternatives = payload.results
    .slice(1, 4)
    .map((item) => `<div class="metric"><span>${item.cipher}</span><strong>${item.confidence}%</strong></div>`)
    .join("");

  elements.analysisPanel.innerHTML = `
    <div class="analysis-result">
      <div class="panel-title">
        <div>
          <p class="eyebrow">Best Match</p>
          <h3>${escapeHtml(best.cipher)}</h3>
        </div>
        <span class="status-pill">${best.confidence}%</span>
      </div>
      <div class="confidence-bar" aria-label="Confidence score">
        <span style="width: ${best.confidence}%"></span>
      </div>
      <div class="result-grid">
        <div class="metric"><span>Encryption Type</span><strong>${escapeHtml(best.cipher)}</strong></div>
        <div class="metric"><span>Confidence Score</span><strong>${best.confidence}%</strong></div>
        <div class="metric"><span>Detected Parameters</span><strong>${escapeHtml(best.parameters)}</strong></div>
        <div class="metric"><span>Possible Plaintext</span><strong>${escapeHtml(best.plaintext)}</strong></div>
      </div>
      <pre>${escapeHtml(best.explanation)}</pre>
      ${alternatives ? `<div class="result-grid">${alternatives}</div>` : ""}
    </div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

elements.cipherForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitter = event.submitter;
  const mode = submitter?.dataset.action || "encrypt";

  setLoading(true);
  elements.resultStatus.textContent = "Working";
  try {
    const payload = await requestJson("/api/cipher", {
      cipher: elements.cipherType.value,
      mode,
      text: elements.inputText.value,
      params: collectParams(),
    });
    state.result = payload.result;
    elements.result.textContent = payload.result;
    elements.resultStatus.textContent = "Complete";
    addHistoryItem({
      cipher: elements.cipherType.options[elements.cipherType.selectedIndex].text,
      mode,
      input: elements.inputText.value,
      result: payload.result,
      timestamp: new Date().toLocaleString(),
    });
    toast(`${mode === "encrypt" ? "Encryption" : "Decryption"} complete.`);
  } catch (error) {
    elements.resultStatus.textContent = "Error";
    toast(error.message, "error");
  } finally {
    setLoading(false);
  }
});

elements.assistantForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoading(true);
  try {
    const payload = await requestJson("/api/analyze", {
      text: elements.assistantInput.value,
    });
    renderAnalysis(payload);
    toast("Analysis complete.");
  } catch (error) {
    toast(error.message, "error");
  } finally {
    setLoading(false);
  }
});

elements.copyResult.addEventListener("click", async () => {
  if (!state.result) {
    toast("There is no result to copy yet.", "error");
    return;
  }
  await navigator.clipboard.writeText(state.result);
  toast("Result copied to clipboard.");
});

elements.downloadResult.addEventListener("click", () => {
  if (!state.result) {
    toast("There is no result to download yet.", "error");
    return;
  }
  const blob = new Blob([state.result], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cipherlab-result.txt";
  link.click();
  URL.revokeObjectURL(url);
  toast("TXT download started.");
});

elements.saveHistory.addEventListener("click", () => {
  if (!state.history.length) {
    toast("There is no history to save yet.", "error");
    return;
  }
  const blob = new Blob([historyToText(state.history)], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cipherlab-history.txt";
  link.click();
  URL.revokeObjectURL(url);
  toast("History TXT download started.");
});

elements.cipherType.addEventListener("change", updateCipherFields);
elements.inputText.addEventListener("input", updateCounters);
elements.assistantInput.addEventListener("input", updateCounters);

elements.navToggle.addEventListener("click", () => {
  const isOpen = elements.navLinks.classList.toggle("open");
  elements.navToggle.setAttribute("aria-expanded", String(isOpen));
});

$$("[data-mode-link]").forEach((link) => {
  link.addEventListener("click", () => {
    elements.navLinks.classList.remove("open");
    elements.navToggle.setAttribute("aria-expanded", "false");
  });
});

updateCipherFields();
updateCounters();
renderHistory(state.history);
