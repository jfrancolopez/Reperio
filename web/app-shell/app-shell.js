// App-shell behavior (RPR-117). Dependency-free, single-origin, and safe:
// all dynamic text is written with textContent and source content is never
// executed or injected into the document.
"use strict";

const MAX_RECONNECT_MS = 30000;
const BASE_RECONNECT_MS = 1000;
const MAX_RECONNECT_ATTEMPTS = 8;

function byId(id) {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error("missing shell element: " + id);
  }
  return element;
}

function setConnectionState(state, label) {
  const node = byId("connection-state");
  node.setAttribute("data-state", state);
  node.textContent = label;
}

function connectEvents(sourceUrl) {
  let attempts = 0;
  let timer = null;

  function open() {
    const events = new EventSource(sourceUrl);
    attempts = 0;
    setConnectionState("connected", "Connected to scanner");

    events.onerror = function () {
      events.close();
      scheduleReconnect();
    };

    events.onopen = function () {
      clearRouteError();
    };
  }

  function scheduleReconnect() {
    if (attempts >= MAX_RECONNECT_ATTEMPTS) {
      setConnectionState("disconnected", "Disconnected — reload to retry");
      return;
    }
    attempts += 1;
    const delay = Math.min(BASE_RECONNECT_MS * 2 ** attempts, MAX_RECONNECT_MS);
    setConnectionState("reconnecting", "Reconnecting in " + delay + " ms");
    if (timer !== null) {
      clearTimeout(timer);
    }
    timer = setTimeout(open, delay);
  }

  setConnectionState("connecting", "Connecting to scanner…");
  open();
  return { close: function () { if (timer !== null) { clearTimeout(timer); } } };
}

function showRouteLoading() {
  byId("route-view").setAttribute("aria-busy", "true");
}

function hideRouteLoading() {
  byId("route-view").setAttribute("aria-busy", "false");
}

function showRouteError(message) {
  const node = byId("route-error");
  node.textContent = message || "This view could not be loaded.";
  node.hidden = false;
  hideRouteLoading();
}

function clearRouteError() {
  const node = byId("route-error");
  node.textContent = "";
  node.hidden = true;
}

function setCaseContext(caseName, sourceName) {
  byId("case-name").textContent = caseName || "No case";
  byId("source-name").textContent = sourceName || "No source selected";
}

function initAppShell() {
  window.reperio = {
    connectEvents: connectEvents,
    showRouteLoading: showRouteLoading,
    hideRouteLoading: hideRouteLoading,
    showRouteError: showRouteError,
    clearRouteError: clearRouteError,
    setCaseContext: setCaseContext,
  };
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initAppShell);
} else {
  initAppShell();
}
