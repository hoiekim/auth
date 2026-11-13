(function () {
  "use strict";

  // Passkey sign-in on /login, and the passkey step of /reset/confirm.

  function toBuffer(b64url) {
    var s = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function toB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function requestOptions(json) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
      return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    var o = Object.assign({}, json, { challenge: toBuffer(json.challenge) });
    if (json.allowCredentials) {
      o.allowCredentials = json.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: toBuffer(c.id) });
      });
    }
    return o;
  }

  function assertionJSON(cred) {
    if (typeof cred.toJSON === "function") {
      try {
        return cred.toJSON();
      } catch (e) {
        // Fall through to the manual form.
      }
    }
    var r = cred.response;
    return {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: toB64url(r.clientDataJSON),
        authenticatorData: toB64url(r.authenticatorData),
        signature: toB64url(r.signature),
        userHandle: r.userHandle ? toB64url(r.userHandle) : undefined,
      },
    };
  }

  async function postJSON(url, body) {
    var res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
    var data = null;
    try {
      data = await res.json();
    } catch (e) {
      data = null;
    }
    if (!res.ok) {
      throw new Error((data && data.error_description) || "The request failed (" + res.status + ").");
    }
    return data;
  }

  async function getAssertion() {
    var opts = await postJSON("/login/passkey/options", {});
    var cred = await navigator.credentials.get({ publicKey: requestOptions(opts.options) });
    if (!cred) throw new Error("No passkey was chosen.");
    return assertionJSON(cred);
  }

  function showError(el, err) {
    if (!el) return;
    var msg = err && err.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out." : (err && err.message) || "That didn't work.";
    el.textContent = msg;
    el.hidden = false;
  }

  var supported = typeof window.PublicKeyCredential === "function" && navigator.credentials;

  var signin = document.getElementById("passkey-signin");
  if (signin && supported) {
    var box = document.querySelector(".passkey");
    if (box) box.hidden = false;
    var errorEl = document.getElementById("passkey-error");
    signin.addEventListener("click", async function () {
      if (errorEl) errorEl.hidden = true;
      signin.disabled = true;
      try {
        var response = await getAssertion();
        var done = await postJSON("/login/passkey", { response: response, return_to: signin.dataset.returnTo || "/account" });
        location.assign(done.redirect || "/account");
      } catch (err) {
        showError(errorEl, err);
        signin.disabled = false;
      }
    });
  }

  var confirm = document.getElementById("passkey-confirm");
  if (confirm) {
    var confirmError = document.getElementById("passkey-error");
    if (!supported) {
      confirm.hidden = true;
    } else {
      confirm.addEventListener("click", async function () {
        if (confirmError) confirmError.hidden = true;
        var form = document.getElementById("reset-form");
        var field = document.getElementById("passkey-response");
        if (!form || !field) return;
        if (!form.reportValidity()) return;
        confirm.disabled = true;
        try {
          field.value = JSON.stringify(await getAssertion());
          form.submit();
        } catch (err) {
          showError(confirmError, err);
          confirm.disabled = false;
        }
      });
    }
  }
})();
