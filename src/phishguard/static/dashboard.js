"use strict";

const MODES = {
  email: {
    field: "content",
    endpoint: "/v1/analyze/email",
    label: "Paste the email subject and body",
    help: "Plain text only. HTML is analyzed, never rendered.",
    placeholder:
      "Subject: Urgent account warning\n\nWe detected unusual activity. Click here to verify your password immediately...",
    example:
      "Subject: Urgent account warning\n\nClick here immediately to verify your account password or access will be suspended.",
    maximum: 50000,
  },
  url: {
    field: "url",
    endpoint: "/v1/analyze/url",
    label: "Paste a website URL or domain",
    help: "The address is inspected as text and never visited. Bare domains assume HTTPS.",
    placeholder: "https://example.com/account/verify",
    example: "http://192.0.2.10/login/verify-account/password",
    maximum: 2048,
  },
};

const ACTION_TITLES = {
  allow: "Continue with normal caution",
  warn: "Pause and verify independently",
  quarantine: "Do not interact—send for review",
  block: "Block or isolate this content",
};

const GAUGE_COLORS = {
  legitimate: "#63e6a5",
  suspicious: "#ffc970",
  phishing: "#ff6e76",
};

const state = { mode: "email" };
const form = document.querySelector("#analysis-form");
const input = document.querySelector("#analysis-input");
const inputLabel = document.querySelector("#input-label");
const inputHelp = document.querySelector("#input-help");
const characterCount = document.querySelector("#character-count");
const formMessage = document.querySelector("#form-message");
const analyzeButton = document.querySelector("#analyze-button");
const buttonLabel = analyzeButton.querySelector(".button-label");
const panel = document.querySelector("#analysis-panel");
const emptyResult = document.querySelector("#empty-result");
const resultCard = document.querySelector("#result-card");

function formatNumber(value) {
  const number = Number(value);
  const sign = number > 0 ? "+" : "";
  return `${sign}${number.toFixed(3)}`;
}

function setText(selector, value) {
  const element = document.querySelector(selector);
  element.textContent = String(value);
}

function clearList(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

function renderTextList(element, values, formatter) {
  clearList(element);
  if (!values.length) {
    const item = document.createElement("li");
    item.textContent = "No strong active signal in this direction.";
    element.appendChild(item);
    return;
  }
  values.forEach((value) => {
    const item = document.createElement("li");
    formatter(item, value);
    element.appendChild(item);
  });
}

function renderResult(result) {
  emptyResult.hidden = true;
  resultCard.hidden = false;

  const gauge = document.querySelector("#risk-gauge");
  gauge.style.setProperty("--score", result.risk_score);
  gauge.style.setProperty("--gauge-color", GAUGE_COLORS[result.classification]);
  setText("#risk-score", result.risk_score);

  const badge = document.querySelector("#classification");
  badge.textContent = result.classification;
  badge.style.color = GAUGE_COLORS[result.classification];
  setText("#action-title", ACTION_TITLES[result.recommended_action]);
  setText("#guidance", result.guidance);

  const reasons = document.querySelector("#reason-list");
  renderTextList(reasons, result.reasons, (item, reason) => {
    item.textContent = reason;
  });
  setText(
    "#evidence-count",
    `${result.evidence.length} ${result.evidence.length === 1 ? "signal" : "signals"}`,
  );

  const renderFeature = (item, feature) => {
    const name = document.createElement("span");
    const contribution = document.createElement("span");
    name.textContent = feature.feature;
    contribution.textContent = formatNumber(feature.contribution);
    item.append(name, contribution);
  };
  renderTextList(
    document.querySelector("#supporting-features"),
    result.supporting_model_features,
    renderFeature,
  );
  renderTextList(
    document.querySelector("#mitigating-features"),
    result.mitigating_model_features,
    renderFeature,
  );
  setText(
    "#result-version",
    `Model ${result.model_version} · Policy ${result.policy_version} · Advisory only`,
  );
}

function setMode(mode) {
  state.mode = mode;
  const config = MODES[mode];
  document.querySelectorAll(".mode-tab").forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  const activeTab = document.querySelector(`.mode-tab[data-mode="${mode}"]`);
  panel.setAttribute("aria-labelledby", activeTab.id);
  input.name = config.field;
  input.maxLength = config.maximum;
  input.placeholder = config.placeholder;
  inputLabel.textContent = config.label;
  inputHelp.textContent = config.help;
  input.value = "";
  formMessage.textContent = "";
  resultCard.hidden = true;
  emptyResult.hidden = false;
  updateCharacterCount();
}

function updateCharacterCount() {
  const maximum = MODES[state.mode].maximum;
  characterCount.textContent = `${input.value.length.toLocaleString()} / ${maximum.toLocaleString()}`;
}

function setLoading(loading) {
  analyzeButton.disabled = loading;
  buttonLabel.textContent = loading ? "Analyzing signals…" : "Analyze risk";
  form.setAttribute("aria-busy", String(loading));
}

async function analyze(event) {
  event.preventDefault();
  const config = MODES[state.mode];
  const value = input.value.trim();
  formMessage.textContent = "";
  if (!value) {
    formMessage.textContent = `Enter ${state.mode === "email" ? "email content" : "a URL"} to analyze.`;
    input.focus();
    return;
  }

  setLoading(true);
  try {
    const response = await fetch(config.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [config.field]: value }),
    });
    if (!response.ok) {
      const message = response.status === 503
        ? "Detection models are not ready. Build the local artifacts, then try again."
        : "The analysis could not be completed. Check the input and try again.";
      throw new Error(message);
    }
    const result = await response.json();
    renderResult(result);
    resultCard.focus({ preventScroll: true });
  } catch (error) {
    formMessage.textContent = error instanceof Error
      ? error.message
      : "The analysis could not be completed.";
  } finally {
    setLoading(false);
  }
}

document.querySelectorAll(".mode-tab").forEach((tab) => {
  tab.addEventListener("click", () => setMode(tab.dataset.mode));
  tab.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight"].includes(event.key)) {
      return;
    }
    event.preventDefault();
    const nextMode = state.mode === "email" ? "url" : "email";
    setMode(nextMode);
    document.querySelector(`.mode-tab[data-mode="${nextMode}"]`).focus();
  });
});

document.querySelector("#example-button").addEventListener("click", () => {
  input.value = MODES[state.mode].example;
  updateCharacterCount();
  input.focus();
});

document.querySelector("#new-analysis").addEventListener("click", () => {
  resultCard.hidden = true;
  emptyResult.hidden = false;
  input.value = "";
  updateCharacterCount();
  input.focus();
});

input.addEventListener("input", updateCharacterCount);
form.addEventListener("submit", analyze);
