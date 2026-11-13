(function () {
  "use strict";

  // The account page: calls the /v1/me API with the session cookie and the
  // CSRF token from the page's meta tag. Secrets shown once are never stored.

  var root = document.getElementById("app");
  if (!root) return;
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrf = csrfMeta ? csrfMeta.getAttribute("content") || "" : "";
  var me = null;

  // ------------------------------------------------------------ helpers

  function el(tag, attrs) {
    var node = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v === undefined || v === null || v === false) return;
      if (k === "class") node.className = v;
      else if (k === "hidden") node.hidden = !!v;
      else if (k.slice(0, 2) === "on" && typeof v === "function") node.addEventListener(k.slice(2), v);
      else if (k === "checked" || k === "value" || k === "disabled" || k === "selected") node[k] = v;
      else node.setAttribute(k, v === true ? "" : String(v));
    });
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) {
      child.forEach(function (c) {
        append(node, c);
      });
      return;
    }
    node.append(child instanceof Node ? child : String(child));
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function when(iso) {
    if (!iso) return "never";
    var d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function ApiError(status, code, description) {
    this.status = status;
    this.code = code;
    this.message = description;
  }
  ApiError.prototype = Object.create(Error.prototype);

  function goToLogin(reauth) {
    var params = new URLSearchParams({ return_to: location.pathname + location.hash });
    if (reauth) {
      params.set("reauth", "1");
      if (me && me.username) params.set("login_hint", me.username);
    }
    location.assign("/login?" + params.toString());
  }

  async function api(method, path, body) {
    var init = { method: method, credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET") {
      init.headers["Content-Type"] = "application/json";
      init.headers["X-CSRF-Token"] = csrf;
      init.body = JSON.stringify(body || {});
    }
    var res = await fetch(path, init);
    var data = null;
    if (res.status !== 204) {
      try {
        data = await res.json();
      } catch (e) {
        data = null;
      }
    }
    if (res.ok) return data;
    var code = data && data.error;
    if (res.status === 401) {
      goToLogin(false);
      throw new ApiError(401, code, "Sign in first.");
    }
    if (res.status === 403 && code === "reauth_required") {
      goToLogin(true);
      throw new ApiError(403, code, "Sign in again to make this change.");
    }
    throw new ApiError(res.status, code, (data && data.error_description) || "The request failed (" + res.status + ").");
  }

  // A step-up (adding a second factor) gives the session a new token, and the
  // CSRF token derives from it: read the new one from a fresh copy of this page.
  async function refreshCsrf() {
    try {
      var res = await fetch(location.pathname, { credentials: "same-origin" });
      var doc = new DOMParser().parseFromString(await res.text(), "text/html");
      var m = doc.querySelector('meta[name="csrf-token"]');
      if (m) {
        csrf = m.getAttribute("content") || csrf;
        if (csrfMeta) csrfMeta.setAttribute("content", csrf);
      }
    } catch (e) {
      // The next change fails with a CSRF error and a reload fixes it.
    }
  }

  function status() {
    return el("p", { class: "error", role: "alert", hidden: true });
  }

  function say(node, message, kind) {
    node.className = kind === "ok" ? "notice" : "error";
    node.textContent = message;
    node.hidden = !message;
  }

  // Runs an action with its button disabled, and shows a failure in `out`.
  async function act(button, out, fn) {
    if (out) say(out, "");
    if (button) button.disabled = true;
    try {
      await fn();
    } catch (e) {
      if (out && !(e instanceof ApiError && (e.status === 401 || e.code === "reauth_required"))) {
        var msg = e && e.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out." : (e && e.message) || "That didn't work.";
        say(out, msg);
      }
    } finally {
      if (button) button.disabled = false;
    }
  }

  function secretBox(title, value, note) {
    var copy = el("button", { type: "button", class: "secondary" }, "Copy");
    copy.addEventListener("click", async function () {
      try {
        await navigator.clipboard.writeText(value);
        copy.textContent = "Copied";
      } catch (e) {
        copy.textContent = "Select the text and copy it";
      }
    });
    var box = el(
      "div",
      { class: "secret", role: "status" },
      el("strong", {}, title),
      el("p", { class: "hint" }, note || "Shown only now. Copy it somewhere safe before you leave this page."),
      el("pre", {}, value),
    );
    var done = el("button", { type: "button", class: "secondary" }, "Done");
    done.addEventListener("click", function () {
      box.remove();
    });
    box.append(el("div", { class: "actions" }, copy, done));
    return box;
  }

  function section(id, title) {
    var s = el("section", { id: id, "aria-labelledby": id + "-title" }, el("h2", { id: id + "-title" }, title));
    root.append(s);
    return s;
  }

  function slot(parent) {
    var d = el("div");
    parent.append(d);
    return d;
  }

  // ----------------------------------------------------------- WebAuthn

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

  function creationOptions(json) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
      return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    var o = Object.assign({}, json, {
      challenge: toBuffer(json.challenge),
      user: Object.assign({}, json.user, { id: toBuffer(json.user.id) }),
    });
    if (json.excludeCredentials) {
      o.excludeCredentials = json.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: toBuffer(c.id) });
      });
    }
    return o;
  }

  function registrationJSON(cred) {
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
        attestationObject: toB64url(r.attestationObject),
        transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
      },
    };
  }

  // ------------------------------------------------------------ profile

  function renderProfile(s) {
    var out = status();
    var name = el("input", { name: "name", autocomplete: "name", maxlength: "200", value: me.name || "" });
    var email = el("input", { name: "email", type: "email", autocomplete: "email", maxlength: "254", value: me.email || "" });
    var save = el("button", { type: "submit" }, "Save");
    var form = el(
      "form",
      {},
      el("p", { class: "muted" }, "Username: ", el("strong", {}, me.username), " (it never changes)"),
      el("label", {}, "Name", name),
      el("label", {}, "Recovery email", email),
      me.email && !me.email_verified ? el("p", { class: "hint" }, "This address isn't confirmed yet.") : null,
      me.email_pending ? el("p", { class: "hint" }, "Waiting for confirmation: " + me.email_pending + ". Open the link we sent there.") : null,
      save,
      out,
    );
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(save, out, async function () {
        var body = {};
        if (name.value.trim() !== (me.name || "")) body.name = name.value.trim();
        if (email.value.trim() && email.value.trim().toLowerCase() !== (me.email || "").toLowerCase()) body.email = email.value.trim();
        if (Object.keys(body).length === 0) return say(out, "Nothing changed.", "ok");
        me = await api("PATCH", "/v1/me", body);
        await render();
        var msg = body.email ? "Saved. We sent a confirmation link to " + body.email + "." : "Saved.";
        say(document.querySelector("#profile [role=alert]") || out, msg, "ok");
      });
    });
    s.append(form);
  }

  // ----------------------------------------------------------- security

  function renderPassword(s) {
    var out = status();
    var current = el("input", { type: "password", autocomplete: "current-password", maxlength: "1024" });
    var next = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12", maxlength: "256" });
    var hidden = el("input", { type: "text", autocomplete: "username", value: me.username, hidden: true, readonly: true });
    var save = el("button", { type: "submit" }, "Change password");
    var form = el("form", {}, hidden, el("label", {}, "Current password", current), el("label", {}, "New password (12 or more characters)", next), save, out);
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(save, out, async function () {
        await api("POST", "/v1/me/password", { current: current.value, new: next.value });
        current.value = "";
        next.value = "";
        say(out, "Password changed. Your other devices were signed out.", "ok");
      });
    });
    s.append(el("h3", {}, "Password"), form);
  }

  function renderTotp(s) {
    var box = slot(s);
    var out = status();
    s.append(out);
    box.append(el("h3", {}, "Authenticator app"));
    if (me.mfa.totp) {
      var remove = el("button", { type: "button", class: "danger" }, "Remove authenticator app");
      remove.addEventListener("click", function () {
        if (!confirm("Remove the authenticator app? Services that need a second factor will ask you to set one up again.")) return;
        act(remove, out, async function () {
          await api("DELETE", "/v1/me/totp");
          await reload();
        });
      });
      box.append(el("p", { class: "ok" }, "Set up."), remove);
      return;
    }
    var start = el("button", { type: "button" }, "Set up an authenticator app");
    box.append(el("p", { class: "muted" }, "Not set up."), start);
    start.addEventListener("click", function () {
      act(start, out, async function () {
        var e = await api("POST", "/v1/me/totp", {});
        start.hidden = true;
        var code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: "6", required: true });
        var confirmBtn = el("button", { type: "submit" }, "Confirm");
        var form = el("form", {}, el("label", {}, "The 6-digit code your app shows", code), confirmBtn);
        var link = el("a", { href: e.otpauth_uri }, "Open in an authenticator app");
        box.append(
          el(
            "div",
            { class: "secret", role: "status" },
            el("strong", {}, "Add this account to your authenticator app"),
            el("p", { class: "hint" }, "Enter this key in the app, or open the link on the device that has it. Shown only now."),
            el("pre", {}, e.secret),
            el("p", {}, link),
          ),
          form,
        );
        code.focus();
        form.addEventListener("submit", function (ev) {
          ev.preventDefault();
          act(confirmBtn, out, async function () {
            var done = await api("POST", "/v1/me/totp", { enrollment: e.enrollment, code: code.value.trim() });
            await refreshCsrf();
            me = await api("GET", "/v1/me");
            await render();
            var sec = document.getElementById("security");
            var msg = el("p", { class: "notice", role: "status" }, "Authenticator app set up.");
            sec.insertBefore(msg, sec.children[1] || null);
            if (done && done.recovery_codes) {
              sec.insertBefore(
                secretBox("Your recovery codes", done.recovery_codes.join("\n"), "Each works once, in place of a code from your app. Shown only now: keep them somewhere safe."),
                msg.nextSibling,
              );
            }
          });
        });
      });
    });
  }

  function renderRecovery(s) {
    var out = status();
    var regen = el("button", { type: "button", class: "secondary" }, me.mfa.recovery_codes ? "Make new recovery codes" : "Make recovery codes");
    var holder = slot(s);
    regen.addEventListener("click", function () {
      if (me.mfa.recovery_codes && !confirm("Make new recovery codes? The ones you have stop working.")) return;
      act(regen, out, async function () {
        var r = await api("POST", "/v1/me/recovery-codes", {});
        me.mfa.recovery_codes = r.codes.length;
        clear(holder);
        holder.append(secretBox("Your recovery codes", r.codes.join("\n"), "Each works once. Shown only now: keep them somewhere safe."));
      });
    });
    s.append(
      el("h3", {}, "Recovery codes"),
      el("p", { class: "muted" }, me.mfa.recovery_codes + " unused code" + (me.mfa.recovery_codes === 1 ? "" : "s") + " left."),
      regen,
      out,
    );
    s.append(holder);
  }

  async function renderPasskeys(s) {
    var out = status();
    var list = el("ul", { class: "rows" });
    s.append(el("h3", {}, "Passkeys"), list);
    var supported = typeof window.PublicKeyCredential === "function" && navigator.credentials;
    var name = el("input", { maxlength: "100", placeholder: "e.g. Laptop", value: "" });
    var add = el("button", { type: "submit" }, "Add a passkey");
    var form = el("form", { class: "inline" }, el("label", {}, "Name", name), add);
    if (!supported) form.hidden = true;
    s.append(form, out);
    async function load() {
      var data = await api("GET", "/v1/me/passkeys");
      clear(list);
      if (data.items.length === 0) list.append(el("li", {}, el("span", { class: "muted" }, "No passkeys.")));
      data.items.forEach(function (p) {
        var rm = el("button", { type: "button", class: "danger" }, "Remove");
        rm.addEventListener("click", function () {
          if (!confirm("Remove the passkey " + p.name + "?")) return;
          act(rm, out, async function () {
            await api("DELETE", "/v1/me/passkeys/" + encodeURIComponent(p.id));
            await load();
          });
        });
        list.append(el("li", {}, el("div", {}, el("strong", {}, p.name), el("p", { class: "hint" }, "Added " + when(p.created_at) + " · last used " + when(p.last_used_at))), rm));
      });
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(add, out, async function () {
        var begin = await api("POST", "/v1/me/passkeys", {});
        var cred = await navigator.credentials.create({ publicKey: creationOptions(begin.options) });
        if (!cred) throw new Error("No passkey was made.");
        await api("POST", "/v1/me/passkeys", { registration: begin.registration, response: registrationJSON(cred), name: name.value.trim() || "Passkey" });
        name.value = "";
        say(out, "Passkey added.", "ok");
        await load();
      });
    });
    await load();
  }

  // ------------------------------------------------------------ devices

  async function renderDevices(s) {
    var out = status();
    var list = el("ul", { class: "rows" });
    var all = el("button", { type: "button", class: "danger" }, "Sign out everywhere");
    s.append(list, all, out);
    all.addEventListener("click", function () {
      if (!confirm("Sign out of every device, this one included?")) return;
      act(all, out, async function () {
        await api("DELETE", "/v1/me/sessions");
        location.assign("/login");
      });
    });
    async function load() {
      var data = await api("GET", "/v1/me/sessions");
      clear(list);
      data.items.forEach(function (d) {
        var end = el("button", { type: "button", class: "secondary" }, d.current ? "Sign out" : "Sign out this device");
        end.addEventListener("click", function () {
          act(end, out, async function () {
            await api("DELETE", "/v1/me/sessions/" + encodeURIComponent(d.id));
            if (d.current) location.assign("/login");
            else await load();
          });
        });
        var title = d.client ? "App: " + d.client : d.user_agent || "Unknown browser";
        list.append(
          el(
            "li",
            {},
            el(
              "div",
              {},
              el("strong", {}, title),
              d.current ? el("span", { class: "tag" }, "this device") : null,
              el("p", { class: "hint" }, "Signed in " + when(d.created_at) + " · last seen " + when(d.last_seen_at) + (d.ip ? " · " + d.ip : "")),
            ),
            end,
          ),
        );
      });
    }
    await load();
  }

  // ------------------------------------------------------------- access

  var accessItems = [];

  async function renderAccess(s) {
    var data = await api("GET", "/v1/me/access");
    accessItems = data.items;
    var list = el("ul", { class: "rows" });
    if (accessItems.length === 0) list.append(el("li", {}, el("span", { class: "muted" }, "You don't have access to any service yet.")));
    accessItems.forEach(function (a) {
      list.append(el("li", {}, el("div", {}, el("strong", {}, a.service), el("span", { class: "tag" }, a.role)), el("span", { class: "hint" }, "since " + when(a.granted_at))));
    });
    s.append(list);
  }

  // --------------------------------------------- app passwords, API keys

  function renderCredentials(s, kind) {
    var isApw = kind === "app-passwords";
    var scopesField = isApw ? "app_password_scopes" : "api_key_scopes";
    var secretField = isApw ? "password" : "key";
    var services = accessItems.filter(function (a) {
      return a[scopesField] && a[scopesField].length > 0;
    });
    var out = status();
    var list = el("ul", { class: "rows" });
    var created = slot(s);
    s.append(
      el(
        "p",
        { class: "muted" },
        isApw
          ? "For mail, calendar and other apps that can only take a password. Each works for one service and the scopes you choose."
          : "For scripts and tools that call a service's API.",
      ),
    );
    s.append(list);
    async function load() {
      var data = await api("GET", "/v1/me/" + kind);
      clear(list);
      if (data.items.length === 0) list.append(el("li", {}, el("span", { class: "muted" }, "None.")));
      data.items.forEach(function (c) {
        var rm = el("button", { type: "button", class: "danger" }, "Revoke");
        rm.addEventListener("click", function () {
          if (!confirm("Revoke " + c.name + "? Anything using it stops working.")) return;
          act(rm, out, async function () {
            await api("DELETE", "/v1/me/" + kind + "/" + encodeURIComponent(c.id));
            await load();
          });
        });
        var meta = c.service + " · " + c.scopes.join(", ") + " · created " + when(c.created_at) + " · last used " + when(c.last_used_at);
        if (!isApw) meta += c.expires_at ? " · expires " + when(c.expires_at) : " · no expiry";
        list.append(el("li", {}, el("div", {}, el("strong", {}, c.name), isApw ? null : el("code", { class: "hint" }, " " + c.id), el("p", { class: "hint" }, meta)), rm));
      });
    }
    if (services.length === 0) {
      s.append(el("p", { class: "hint" }, "None of your services takes " + (isApw ? "app passwords" : "API keys") + "."), out);
      return load();
    }
    var name = el("input", { required: true, maxlength: "100", placeholder: isApw ? "e.g. Phone mail app" : "e.g. Backup script" });
    var service = el(
      "select",
      {},
      services.map(function (a) {
        return el("option", { value: a.service }, a.service);
      }),
    );
    var scopes = el("fieldset", {}, el("legend", {}, "Scopes"));
    function drawScopes() {
      clear(scopes);
      scopes.append(el("legend", {}, "Scopes"));
      var chosen = services.find(function (a) {
        return a.service === service.value;
      });
      (chosen ? chosen[scopesField] : []).forEach(function (sc) {
        scopes.append(el("label", { class: "check" }, el("input", { type: "checkbox", value: sc, checked: true }), sc));
      });
    }
    service.addEventListener("change", drawScopes);
    drawScopes();
    var expires = el("input", { type: "date" });
    var create = el("button", { type: "submit" }, isApw ? "Create app password" : "Create API key");
    var form = el("form", {}, el("label", {}, "Name", name), el("label", {}, "Service", service), scopes, isApw ? null : el("label", {}, "Expires (optional)", expires), create, out);
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(create, out, async function () {
        var picked = Array.prototype.slice.call(scopes.querySelectorAll("input:checked")).map(function (i) {
          return i.value;
        });
        if (picked.length === 0) throw new Error("Choose at least one scope.");
        var body = { name: name.value.trim(), service: service.value, scopes: picked };
        if (!isApw && expires.value) body.expires_at = expires.value + "T23:59:59Z";
        var c = await api("POST", "/v1/me/" + kind, body);
        name.value = "";
        expires.value = "";
        clear(created);
        created.append(secretBox((isApw ? "App password" : "API key") + " for " + c.service + ": " + c.name, c[secretField]));
        await load();
      });
    });
    s.append(el("h3", {}, isApw ? "New app password" : "New API key"), form);
    return load();
  }

  // ------------------------------------------------------------- delete

  function renderDelete(s) {
    var out = status();
    var del = el("button", { type: "button", class: "danger" }, "Delete my account");
    del.addEventListener("click", function () {
      if (!confirm("Delete your account? This can't be undone, and every service is told to delete or anonymise your data.")) return;
      act(del, out, async function () {
        await api("DELETE", "/v1/me");
        location.assign("/login");
      });
    });
    s.append(el("p", { class: "muted" }, "Deletes your account and signs you out everywhere."), del, out);
  }

  // ------------------------------------------------------------- render

  async function render() {
    clear(root);
    var admin = document.getElementById("admin-link");
    if (admin) admin.hidden = !me.admin;
    root.append(el("h1", {}, "Your account"));
    renderProfile(section("profile", "Profile"));
    var sec = section("security", "Security");
    renderPassword(sec);
    renderTotp(sec);
    renderRecovery(sec);
    var pk = slot(sec);
    var devices = section("devices", "Signed-in devices");
    var access = section("access", "Your services");
    var apw = section("app-passwords", "App passwords");
    var keys = section("api-keys", "API keys");
    if (me.account_deletion) renderDelete(section("delete", "Delete account"));
    var fail = function (where) {
      return function (e) {
        if (e instanceof ApiError && (e.status === 401 || e.code === "reauth_required")) return;
        where.append(el("p", { class: "error", role: "alert" }, (e && e.message) || "Couldn't load this."));
      };
    };
    await Promise.all([renderPasskeys(pk).catch(fail(pk)), renderDevices(devices).catch(fail(devices))]);
    try {
      await renderAccess(access);
      await Promise.all([renderCredentials(apw, "app-passwords").catch(fail(apw)), renderCredentials(keys, "api-keys").catch(fail(keys))]);
    } catch (e) {
      fail(access)(e);
    }
  }

  async function reload() {
    me = await api("GET", "/v1/me");
    await render();
  }

  (async function start() {
    try {
      await reload();
      if (location.hash) {
        var target = document.getElementById(location.hash.slice(1));
        if (target) target.scrollIntoView();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return;
      clear(root);
      root.append(el("p", { class: "error", role: "alert" }, (e && e.message) || "Couldn't load your account."));
    }
  })();
})();
