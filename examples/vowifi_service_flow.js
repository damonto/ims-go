/*
 * TS.43 VoWiFi web portal callback adapter.
 *
 * Carrier WFC/E911 portals are expected to call:
 * - VoWiFiWebServiceFlow.entitlementChanged()
 * - VoWiFiWebServiceFlow.dismissFlow()
 */
(function installVoWiFiServiceFlow(global) {
  "use strict";

  const PREFIX = "TS43_VOWIFI_CALLBACK";
  const STORAGE_KEY = "ims-go.vowifi.callbacks";

  function emit(event) {
    const record = {
      source: "vowifi",
      event,
      href: global.location && global.location.href ? global.location.href : "",
      at: new Date().toISOString(),
    };
    const line = PREFIX + " " + JSON.stringify(record);
    append(record);
    if (global.console && typeof global.console.log === "function") {
      global.console.log(line);
    }
    try {
      global.dispatchEvent(new CustomEvent("vowifi-service-flow-callback", { detail: record }));
    } catch (_) {
      // Some embedded WebViews do not expose CustomEvent.
    }
    return record;
  }

  function append(record) {
    try {
      const existing = JSON.parse(global.localStorage.getItem(STORAGE_KEY) || "[]");
      existing.push(record);
      global.localStorage.setItem(STORAGE_KEY, JSON.stringify(existing.slice(-20)));
    } catch (_) {
      // Console output is the primary path.
    }
  }

  global.VoWiFiWebServiceFlow = Object.assign(
    {
      entitlementChanged: function entitlementChanged() {
        return emit("entitlementChanged");
      },
      dismissFlow: function dismissFlow() {
        return emit("dismissFlow");
      },
    },
    global.VoWiFiWebServiceFlow || {},
  );

  global.vowifiServiceFlow = Object.freeze({
    done: global.VoWiFiWebServiceFlow.entitlementChanged,
    dismiss: global.VoWiFiWebServiceFlow.dismissFlow,
    callbacks: function callbacks() {
      try {
        return JSON.parse(global.localStorage.getItem(STORAGE_KEY) || "[]");
      } catch (_) {
        return [];
      }
    },
  });

  if (global.console && typeof global.console.info === "function") {
    global.console.info("VoWiFiWebServiceFlow adapter installed.");
  }
})(window);
