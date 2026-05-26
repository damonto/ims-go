/*
 * VoWiFi entitlement web portal callback adapter.
 *
 * Paste this script into the carrier web portal console, inject it as a
 * userscript, or load it before the portal page script. It emulates the small
 * JavaScript bridge objects used by Android IMS entitlement WebViews and logs
 * every callback in a stable JSON form.
 *
 * Reference points in refs/:
 * - ImsServiceEntitlement WfcWebPortalFragment:
 *   VoWiFiWebServiceFlow.entitlementChanged(), dismissFlow()
 * - ImsServiceEntitlement WfcQnsWebPortalFragment:
 *   WiFiCallingWebViewController cancel/status/close callbacks
 */
(function installVoWiFiCallbackAdapter(global) {
  "use strict";

  const CALLBACK_LOG_PREFIX = "VOWIFI_CALLBACK";
  const STORAGE_KEY = "ims-client.vowifi.callbacks";

  function now() {
    return new Date().toISOString();
  }

  function toRecord(controller, method, fields) {
    const record = Object.assign(
      {
        source: "vowifi",
        controller,
        method,
        event: eventName(method),
        resultCode: resultCode(method),
        href: global.location && global.location.href ? global.location.href : "",
        at: now(),
      },
      fields || {},
    );
    return record;
  }

  function eventName(method) {
    switch (method) {
      case "entitlementChanged":
        return "entitlementChanged";
      case "dismissFlow":
      case "cancelButtonClicked":
      case "CloseWebView":
      case "closeWebView":
      case "onCloseWebView":
        return "dismissFlow";
      default:
        return method;
    }
  }

  function resultCode(method) {
    switch (eventName(method)) {
      case "entitlementChanged":
        return "success";
      case "dismissFlow":
        return "cancel";
      default:
        return undefined;
    }
  }

  function recordCallback(controller, method, args) {
    const record = toRecord(controller, method, { args: Array.from(args || []) });
    appendToStorage(record);
    emit(record);
    return record;
  }

  function appendToStorage(record) {
    try {
      const existing = JSON.parse(global.localStorage.getItem(STORAGE_KEY) || "[]");
      existing.push(record);
      global.localStorage.setItem(STORAGE_KEY, JSON.stringify(existing.slice(-20)));
    } catch (_) {
      // Some carrier pages disable storage. Console/event output still works.
    }
  }

  function emit(record) {
    const line = CALLBACK_LOG_PREFIX + " " + JSON.stringify(record);
    if (global.console && typeof global.console.log === "function") {
      global.console.log(line);
    }
    try {
      global.dispatchEvent(new CustomEvent("vowifi-callback", { detail: record }));
    } catch (_) {
      // CustomEvent can be blocked in older embedded engines.
    }
    try {
      global.name = line;
    } catch (_) {
      // window.name is a convenience channel only.
    }
  }

  function method(controller, name) {
    return function bridgeMethod() {
      return recordCallback(controller, name, arguments);
    };
  }

  function installObject(name, methods) {
    const target = Object.assign({}, global[name] || {});
    for (const methodName of methods) {
      if (typeof target[methodName] !== "function") {
        target[methodName] = method(name, methodName);
      }
    }
    global[name] = target;
    return target;
  }

  const voWiFiWebServiceFlow = installObject("VoWiFiWebServiceFlow", [
    "entitlementChanged",
    "dismissFlow",
  ]);

  const wifiCallingWebViewController = installObject("WiFiCallingWebViewController", [
    "cancelButtonClicked",
    "cancelButtonPressed",
    "phoneServicesAccountStatusChanged",
    "CloseWebView",
    "closeWebView",
    "onCloseWebView",
  ]);

  const nsdsWebSheetController = installObject("NsdsWebSheetController", [
    "entitlementChanged",
    "dismissFlow",
    "cancelButtonClicked",
    "cancelButtonPressed",
    "phoneServicesAccountStatusChanged",
    "CloseWebView",
    "closeWebView",
    "onCloseWebView",
  ]);

  global.vowifiCallback = Object.freeze({
    done: voWiFiWebServiceFlow.entitlementChanged,
    dismiss: voWiFiWebServiceFlow.dismissFlow,
    controllers: Object.freeze({
      VoWiFiWebServiceFlow: voWiFiWebServiceFlow,
      WiFiCallingWebViewController: wifiCallingWebViewController,
      NsdsWebSheetController: nsdsWebSheetController,
    }),
    callbacks: function callbacks() {
      try {
        return JSON.parse(global.localStorage.getItem(STORAGE_KEY) || "[]");
      } catch (_) {
        return [];
      }
    },
  });

  if (global.console && typeof global.console.info === "function") {
    global.console.info(
      "VoWiFi callback adapter installed. Watch for " +
        CALLBACK_LOG_PREFIX +
        " lines, then let examples/main.go keep polling entitlement.",
    );
  }
})(window);
