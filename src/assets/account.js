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
    if (isNaN(d.getTime())) return iso;
    try {
      return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
    } catch (e) {
      return d.toLocaleString();
    }
  }

  // Inline SVG, 16×16 in the text color: the CSP loads no images.
  var SVG = "http://www.w3.org/2000/svg";
  var ICONS = {
    info: [["circle", { cx: 8, cy: 8, r: 6.25 }], ["path", { d: "M8 7.25v3.5M8 5v.25" }]],
    alert: [["path", { d: "M8 2.25 1.75 13.25h12.5L8 2.25ZM8 6.5v3M8 11.25v.25" }]],
    check: [["circle", { cx: 8, cy: 8, r: 6.25 }], ["path", { d: "m5.5 8.25 1.75 1.75 3.25-3.5" }]],
    done: [["path", { d: "m3 8.5 3.25 3.25L13 5" }]],
    person: [["circle", { cx: 8, cy: 5.25, r: 2.75 }], ["path", { d: "M2.75 14c.55-2.85 2.6-4.5 5.25-4.5s4.7 1.65 5.25 4.5" }]],
    shield: [["path", { d: "M8 1.75 2.75 3.5v4.25c0 3.1 2.15 5.4 5.25 6.5 3.1-1.1 5.25-3.4 5.25-6.5V3.5L8 1.75Z" }]],
    monitor: [["rect", { x: 1.75, y: 2.5, width: 12.5, height: 8.5, rx: 1.25 }], ["path", { d: "M5.75 13.75h4.5M8 11v2.75" }]],
    phone: [["rect", { x: 4.25, y: 1.75, width: 7.5, height: 12.5, rx: 1.5 }], ["path", { d: "M7.25 11.75h1.5" }]],
    apps: [
      ["rect", { x: 2, y: 2, width: 5, height: 5, rx: 1.25 }],
      ["rect", { x: 9, y: 2, width: 5, height: 5, rx: 1.25 }],
      ["rect", { x: 2, y: 9, width: 5, height: 5, rx: 1.25 }],
      ["rect", { x: 9, y: 9, width: 5, height: 5, rx: 1.25 }],
    ],
    lock: [["rect", { x: 2.75, y: 7, width: 10.5, height: 7.25, rx: 1.5 }], ["path", { d: "M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" }]],
    key: [["circle", { cx: 5, cy: 11, r: 2.75 }], ["path", { d: "m7 9 6.25-6.25M11 4.75l1.75 1.75M9.5 6.25l1.25 1.25" }]],
    passkey: [
      ["circle", { cx: 6, cy: 5, r: 2.5 }],
      ["path", { d: "M1.75 13.25c.4-2.4 2.1-3.75 4.25-3.75.8 0 1.5.2 2.1.5" }],
      ["circle", { cx: 12, cy: 8.25, r: 1.75 }],
      ["path", { d: "M12 10v3.75M12 12.25h1.25" }],
    ],
    copy: [
      ["rect", { x: 5.25, y: 5.25, width: 9, height: 9, rx: 1.5 }],
      ["path", { d: "M10.75 5.25v-2c0-.8-.7-1.5-1.5-1.5h-6c-.8 0-1.5.7-1.5 1.5v6c0 .8.7 1.5 1.5 1.5h2" }],
    ],
  };

  function icon(name, size) {
    var svg = document.createElementNS(SVG, "svg");
    var s = String(size || 16);
    var attrs = {
      class: "icon",
      width: s,
      height: s,
      viewBox: "0 0 16 16",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "1.5",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
      focusable: "false",
    };
    Object.keys(attrs).forEach(function (k) {
      svg.setAttribute(k, attrs[k]);
    });
    (ICONS[name] || []).forEach(function (shape) {
      var n = document.createElementNS(SVG, shape[0]);
      Object.keys(shape[1]).forEach(function (k) {
        n.setAttribute(k, String(shape[1][k]));
      });
      svg.append(n);
    });
    return svg;
  }

  function tag(text, kind) {
    return el("span", { class: kind ? "tag " + kind : "tag" }, text);
  }

  function initials(name, username) {
    var words = (name || "").trim().split(/\s+/).filter(Boolean);
    var first = function (w) {
      return Array.from(w)[0] || "";
    };
    var s = words.length ? first(words[0]) + (words.length > 1 ? first(words[words.length - 1]) : "") : first(username || "?");
    return s.toUpperCase();
  }

  // "Chrome on macOS" from a user agent; the full string stays in the tooltip.
  function deviceName(ua) {
    if (!ua) return "Unknown browser";
    var browser = /Edg(e|A|iOS)?\//.test(ua)
      ? "Edge"
      : /OPR\//.test(ua)
        ? "Opera"
        : /(Firefox|FxiOS)\//.test(ua)
          ? "Firefox"
          : /(Chrome|CriOS)\//.test(ua)
            ? "Chrome"
            : /Safari\//.test(ua)
              ? "Safari"
              : null;
    var os = /iPhone|iPad|iPod/.test(ua)
      ? "iOS"
      : /Android/.test(ua)
        ? "Android"
        : /CrOS/.test(ua)
          ? "ChromeOS"
          : /Windows/.test(ua)
            ? "Windows"
            : /Mac OS X|Macintosh/.test(ua)
              ? "macOS"
              : /Linux/.test(ua)
                ? "Linux"
                : null;
    if (!browser && !os) return ua.length > 60 ? ua.slice(0, 60) + "…" : ua;
    return (browser || "Browser") + (os ? " on " + os : "");
  }

  function ApiError(status, code, description) {
    this.status = status;
    this.code = code;
    this.message = description;
  }
  ApiError.prototype = Object.create(Error.prototype);

  // `resume` marks the way back, so the page knows to carry on with the
  // change noted before leaving (signInAgain).
  function goToLogin(reauth, resume) {
    var params = new URLSearchParams({ return_to: location.pathname + (resume ? "?resume=1" : "") + location.hash });
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
    // reauth_required is act's to handle: it knows which change asked.
    throw new ApiError(res.status, code, (data && data.error_description) || "The request failed (" + res.status + ").");
  }

  // ------------------------------------------ signing in again, and on

  // A change that needs a recent sign-in (§7.5) sends the browser to sign in
  // again, and the sign-in brings it back here. The change, a form or button
  // marked data-resume, is noted in this tab for the trip and starts again
  // once the page is back, so it carries on instead of being lost. Its form's
  // values go with it, but never a password: a form with one waits for it to
  // be typed again. It carries on only for the same person, within
  // RESUME_MS, and once: if it still needs a sign-in, it says why instead.
  var RESUME = "auth.resume";
  var RESUME_MS = 10 * 60 * 1000;
  var resuming = false;

  function fieldsOf(node) {
    if (node.tagName !== "FORM") return [];
    return Array.prototype.filter.call(node.elements, function (f) {
      return f.tagName === "INPUT" || f.tagName === "SELECT" || f.tagName === "TEXTAREA";
    });
  }

  function fieldKind(f) {
    return f.tagName + ":" + f.type + (f.type === "checkbox" ? ":" + f.value : "");
  }

  function signInAgain(trigger) {
    var noted = false;
    if (trigger && me) {
      try {
        sessionStorage.setItem(
          RESUME,
          JSON.stringify({
            page: location.pathname,
            user: me.id,
            action: trigger.getAttribute("data-resume"),
            at: Date.now(),
            fields: fieldsOf(trigger).map(function (f) {
              return [fieldKind(f), f.type === "password" ? null : f.type === "checkbox" ? f.checked : f.value];
            }),
          }),
        );
        noted = true;
      } catch (e) {
        // Without storage the page comes back as before, without the change.
      }
    }
    goToLogin(true, noted);
  }

  // The change noted before signing in again, when this load is the way back
  // from that sign-in. Taken once, so a reload doesn't start it again.
  function takeNoted() {
    var back = new URLSearchParams(location.search).has("resume");
    if (back) history.replaceState(null, "", location.pathname + location.hash);
    var saved = null;
    try {
      saved = JSON.parse(sessionStorage.getItem(RESUME) || "null");
      sessionStorage.removeItem(RESUME);
    } catch (e) {
      return null;
    }
    if (!back || !saved || saved.page !== location.pathname || typeof saved.action !== "string" || !Array.isArray(saved.fields)) return null;
    var age = Date.now() - saved.at;
    return age >= 0 && age < RESUME_MS ? saved : null;
  }

  function carryOn(saved) {
    if (!saved || !me || saved.user !== me.id) return;
    var target = Array.prototype.find.call(root.querySelectorAll("[data-resume]"), function (n) {
      return n.getAttribute("data-resume") === saved.action;
    });
    if (!target) return;
    var whole = true;
    var retype = null;
    saved.fields.forEach(function (s, i) {
      // Read the fields again each time: choosing a service redraws its scopes.
      var f = fieldsOf(target)[i];
      if (!whole || !f || fieldKind(f) !== s[0]) {
        whole = false;
        return;
      }
      if (s[1] === null) retype = retype || f;
      else if (f.type === "checkbox") f.checked = s[1];
      else {
        f.value = s[1];
        if (f.tagName === "SELECT") f.dispatchEvent(new Event("change"));
      }
    });
    if (fieldsOf(target).length !== saved.fields.length) whole = false;
    target.scrollIntoView({ block: "center" });
    if (!whole || retype) {
      (retype || fieldsOf(target)[0] || target).focus();
      return;
    }
    // A click or submit runs its handler, and so act, before it returns.
    resuming = true;
    try {
      if (target.tagName === "FORM") target.requestSubmit();
      else target.click();
    } finally {
      resuming = false;
    }
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

  // A message box: "success", "notice" or "error".
  function flash(kind, message) {
    var glyph = kind === "success" ? "check" : kind === "notice" ? "info" : "alert";
    return el("p", { class: kind, role: kind === "error" ? "alert" : "status" }, icon(glyph), el("span", {}, message));
  }

  function status() {
    return el("p", { class: "error", role: "alert", hidden: true });
  }

  function say(node, message, kind) {
    node.className = kind === "ok" ? "success" : "error";
    clear(node);
    if (message) node.append(icon(kind === "ok" ? "check" : "alert"), el("span", {}, message));
    node.hidden = !message;
  }

  // Runs an action with its button disabled, and shows a failure in `out`.
  // One that needs a recent sign-in goes to sign in again, and carries on
  // after it (signInAgain).
  async function act(button, out, fn) {
    var again = resuming;
    if (out) say(out, "");
    if (button) button.disabled = true;
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required" && !again) {
        signInAgain(button && button.closest("[data-resume]"));
        return;
      }
      if (out && !(e instanceof ApiError && e.status === 401)) {
        var msg =
          e && e.name === "NotAllowedError"
            ? "The passkey prompt was cancelled or timed out."
            : e && e.name === "InvalidStateError"
              ? "This device or security key already holds a passkey for your account."
              : (e && e.message) || "That didn't work.";
        say(out, msg);
      }
    } finally {
      if (button) button.disabled = false;
    }
  }

  function secretBox(title, value, note, codes) {
    var copy = el("button", { type: "button", class: "secondary sm" }, icon("copy"), "Copy");
    copy.addEventListener("click", async function () {
      clear(copy);
      try {
        await navigator.clipboard.writeText(value);
        copy.append(icon("done"), "Copied");
      } catch (e) {
        copy.append("Select the text and copy it");
      }
    });
    var box = el(
      "div",
      { class: "secret", role: "status" },
      el("strong", {}, icon("key"), title),
      el("p", { class: "hint" }, note || "Shown only now. Copy it somewhere safe before you leave this page."),
      el("pre", { class: codes ? "codes" : null }, value),
    );
    var done = el("button", { type: "button", class: "secondary sm" }, "Done");
    done.addEventListener("click", function () {
      box.remove();
    });
    box.append(el("div", { class: "actions" }, copy, done));
    return box;
  }

  // A list row: an icon, a title with tags, a line of detail, and actions.
  function row(opts) {
    var lead = el(
      "div",
      { class: "row-lead" },
      opts.icon ? el("span", { class: "row-icon" }, icon(opts.icon)) : null,
      el(
        "div",
        { class: "row-main" },
        el("div", { class: "row-title", title: opts.tooltip || null }, el("span", {}, opts.title), opts.tags || null),
        opts.extra || null,
        opts.detail ? el("p", { class: "hint" }, opts.detail) : null,
      ),
    );
    return el("li", {}, lead, opts.action || null);
  }

  function blank(text) {
    return el("li", { class: "blank" }, text);
  }

  // ---------------------------------------------------- page and panes

  var PANES = [
    ["profile", "Profile", "person"],
    ["security", "Password and authentication", "shield"],
    ["devices", "Devices", "monitor"],
    ["access", "Services", "apps"],
    ["app-passwords", "App passwords", "lock"],
    ["api-keys", "API keys", "key"],
  ];
  var panes = null;

  // Ids inside a pane, such as #delete, open the pane that holds them.
  function paneFor(id) {
    var target = id ? document.getElementById(id) : null;
    var pane = target ? target.closest("section.pane") : null;
    return pane ? pane.id : "profile";
  }

  function showPane() {
    var current = paneFor(location.hash.slice(1));
    Array.prototype.forEach.call(root.querySelectorAll("section.pane"), function (s) {
      s.hidden = s.id !== current;
    });
    Array.prototype.forEach.call(root.querySelectorAll(".side-nav a"), function (a) {
      if (a.getAttribute("href") === "#" + current) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
  }

  window.addEventListener("hashchange", function () {
    if (!me) return;
    showPane();
    var target = location.hash ? document.getElementById(location.hash.slice(1)) : null;
    if (target && !target.classList.contains("pane")) target.scrollIntoView();
    else window.scrollTo(0, 0);
  });

  function section(id, title, lede) {
    var s = el(
      "section",
      { class: "pane", id: id, "aria-labelledby": id + "-title" },
      el("h2", { id: id + "-title" }, title),
      lede ? el("p", { class: "lede" }, lede) : null,
    );
    panes.append(s);
    return s;
  }

  function slot(parent) {
    var d = el("div", { class: "stack" });
    parent.append(d);
    return d;
  }

  function pageHead() {
    return el(
      "div",
      { class: "page-head" },
      el("span", { class: "avatar lg", "aria-hidden": "true" }, initials(me.name, me.username)),
      el(
        "div",
        {},
        el("h1", {}, me.name || me.username, me.name ? el("span", { class: "muted" }, " (" + me.username + ")") : null),
        el("p", {}, "Your personal account"),
      ),
    );
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

  // What unlocks this device's own passkeys, in its maker's words, to name
  // the button that asks for one. Only a label: whether the device can make
  // one at all is the browser's answer (platformPasskeys).
  function deviceUnlock() {
    var ua = navigator.userAgent || "";
    // iPadOS asks for pages as a Mac does, but has a touch screen.
    if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return "Face ID or Touch ID";
    if (/Macintosh/.test(ua)) return "Touch ID";
    if (/Android/.test(ua)) return "fingerprint, face or screen lock";
    if (/Windows/.test(ua)) return "Windows Hello";
    return "this device";
  }

  // Whether this device can keep a passkey itself, unlocked by a biometric or
  // its screen lock. A browser that doesn't answer within a second counts as
  // no, so the page never waits on it.
  function platformPasskeys() {
    return new Promise(function (resolve) {
      setTimeout(resolve, 1000, false);
      try {
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(
          function (ok) {
            resolve(ok === true);
          },
          function () {
            resolve(false);
          },
        );
      } catch (e) {
        resolve(false);
      }
    });
  }

  // ------------------------------------------------------------ profile

  function renderProfile(s) {
    var out = status();
    var name = el("input", { name: "name", autocomplete: "name", maxlength: "200", value: me.name || "" });
    var email = el("input", { name: "email", type: "email", autocomplete: "email", maxlength: "254", value: me.email || "" });
    var save = el("button", { type: "submit" }, "Save");
    var form = el(
      "form",
      { "data-resume": "profile" },
      el("div", { class: "field-static" }, el("span", {}, "Username"), el("span", {}, el("code", {}, me.username), el("span", { class: "hint" }, " · it never changes"))),
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
    var save = el("button", { type: "submit", class: "secondary" }, "Change password");
    var form = el(
      "form",
      { class: "narrow", "data-resume": "password" },
      hidden,
      el("label", {}, "Current password", current),
      el("label", {}, "New password", next),
      el("p", { class: "hint" }, "At least 12 characters. Your other devices are signed out."),
      save,
      out,
    );
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(save, out, async function () {
        await api("POST", "/v1/me/password", { current: current.value, new: next.value });
        current.value = "";
        next.value = "";
        say(out, "Password changed. Your other devices were signed out.", "ok");
      });
    });
    s.append(el("h3", {}, "Change password"), form);
  }

  function renderTotp(box) {
    var line = el("div", { class: "box-row" });
    box.append(line);
    var out = status();
    var main = el(
      "div",
      { class: "row-lead" },
      el("span", { class: "row-icon" }, icon("phone")),
      el(
        "div",
        { class: "row-main" },
        el("div", { class: "row-title" }, el("span", {}, "Authenticator app"), me.mfa.totp ? tag("Configured", "ok") : null),
        el("p", { class: "hint" }, "A 6-digit code from an app on your phone, asked for at each password sign-in."),
      ),
    );
    if (me.mfa.totp) {
      var remove = el("button", { type: "button", class: "danger sm", "data-resume": "totp-remove" }, "Remove");
      remove.addEventListener("click", function () {
        if (!confirm("Remove the authenticator app? Services that need a second factor will ask you to set one up again.")) return;
        act(remove, out, async function () {
          await api("DELETE", "/v1/me/totp");
          await reload();
        });
      });
      line.append(main, remove, out);
      return;
    }
    var start = el("button", { type: "button", class: "sm", "data-resume": "totp-setup" }, "Set up");
    line.append(main, start, out);
    start.addEventListener("click", function () {
      act(start, out, async function () {
        var e = await api("POST", "/v1/me/totp", {});
        start.hidden = true;
        var code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: "6", required: true });
        var confirmBtn = el("button", { type: "submit" }, "Confirm");
        var form = el("form", { class: "inline" }, el("label", {}, "The 6-digit code your app shows", code), confirmBtn);
        var link = el("a", { href: e.otpauth_uri }, "Open in an authenticator app");
        line.insertBefore(
          el(
            "div",
            { class: "row-detail" },
            el(
              "div",
              { class: "secret", role: "status" },
              el("strong", {}, icon("key"), "Add this account to your authenticator app"),
              el("p", { class: "hint" }, "Enter this key in the app, or open the link on the device that has it. Shown only now."),
              el("pre", {}, e.secret),
              el("p", {}, link),
            ),
            form,
          ),
          out,
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
            var msg = flash("success", "Authenticator app set up.");
            sec.insertBefore(msg, sec.children[1] || null);
            if (done && done.recovery_codes) {
              sec.insertBefore(
                secretBox(
                  "Your recovery codes",
                  done.recovery_codes.join("\n"),
                  "Each works once, in place of a code from your app. Shown only now: keep them somewhere safe.",
                  true,
                ),
                msg.nextSibling,
              );
            }
          });
        });
      });
    });
  }

  function renderRecovery(box) {
    var line = el("div", { class: "box-row" });
    box.append(line);
    var out = status();
    var regen = el(
      "button",
      { type: "button", class: "secondary sm", "data-resume": "recovery-codes" },
      me.mfa.recovery_codes ? "Make new recovery codes" : "Make recovery codes",
    );
    var holder = el("div", { class: "row-detail" });
    regen.addEventListener("click", function () {
      if (me.mfa.recovery_codes && !confirm("Make new recovery codes? The ones you have stop working.")) return;
      act(regen, out, async function () {
        var r = await api("POST", "/v1/me/recovery-codes", {});
        me.mfa.recovery_codes = r.codes.length;
        clear(holder);
        holder.append(secretBox("Your recovery codes", r.codes.join("\n"), "Each works once. Shown only now: keep them somewhere safe.", true));
      });
    });
    var left = me.mfa.recovery_codes + " unused code" + (me.mfa.recovery_codes === 1 ? "" : "s") + " left.";
    line.append(
      el(
        "div",
        { class: "row-lead" },
        el("span", { class: "row-icon" }, icon("key")),
        el(
          "div",
          { class: "row-main" },
          el("div", { class: "row-title" }, el("span", {}, "Recovery codes")),
          el("p", { class: "hint" }, left + " Each works once, when you can't use your phone or passkey."),
        ),
      ),
      regen,
      holder,
      out,
    );
  }

  async function renderPasskeys(s) {
    var out = status();
    var list = el("ul", { class: "rows" });
    var supported = typeof window.PublicKeyCredential === "function" && navigator.credentials;
    var name = el("input", { maxlength: "100", placeholder: "e.g. Laptop", value: "" });
    // The authenticator to ask for, kept in the form so that a change resumed
    // after signing in again (signInAgain) asks for the same one.
    var attachment = el("input", { type: "hidden", value: "" });
    var form = el("form", { class: "inline", "data-resume": "passkey-add" }, el("label", {}, "Name", name), attachment);
    function choice(value, label, kind) {
      var onclick = function () {
        attachment.value = value;
      };
      return el("button", { type: "submit", class: kind, value: value, onclick: onclick }, label);
    }
    // A device that can keep a passkey itself gets a button for that, named
    // for what unlocks it, and one for a security key or another device.
    // Otherwise one button leaves the choice to the browser.
    if (supported && (await platformPasskeys())) {
      form.append(choice("platform", "Use " + deviceUnlock()), choice("cross-platform", "Use a security key or another device", "secondary"));
    } else {
      form.append(choice("", "Add a passkey", "secondary"));
    }
    var footer = el("div", { class: "box-footer" }, form);
    if (!supported) footer.hidden = true;
    s.append(
      el("h3", {}, "Passkeys"),
      el("p", { class: "hint" }, "A passkey signs you in with your device's fingerprint, face or screen lock, and counts as two factors."),
      el("div", { class: "box" }, list, footer),
      out,
    );
    async function load() {
      var data = await api("GET", "/v1/me/passkeys");
      clear(list);
      if (data.items.length === 0) list.append(blank("No passkeys yet."));
      data.items.forEach(function (p) {
        var rm = el("button", { type: "button", class: "danger sm", "data-resume": "passkey-remove:" + p.id }, "Remove");
        rm.addEventListener("click", function () {
          if (!confirm("Remove the passkey " + p.name + "?")) return;
          act(rm, out, async function () {
            await api("DELETE", "/v1/me/passkeys/" + encodeURIComponent(p.id));
            await load();
          });
        });
        list.append(row({ icon: "passkey", title: p.name, detail: "Added " + when(p.created_at) + " · last used " + when(p.last_used_at), action: rm }));
      });
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var buttons = form.querySelectorAll("button");
      // A resumed change has no submitter: it shows on the button it asked for.
      var pressed =
        ev.submitter ||
        Array.prototype.find.call(buttons, function (b) {
          return b.value === attachment.value;
        }) ||
        buttons[0];
      act(pressed, out, async function () {
        buttons.forEach(function (b) {
          b.disabled = true;
        });
        try {
          var begin = await api("POST", "/v1/me/passkeys", attachment.value ? { attachment: attachment.value } : {});
          var cred = await navigator.credentials.create({ publicKey: creationOptions(begin.options) });
          if (!cred) throw new Error("No passkey was made.");
          await api("POST", "/v1/me/passkeys", { registration: begin.registration, response: registrationJSON(cred), name: name.value.trim() || "Passkey" });
          name.value = "";
          say(out, "Passkey added.", "ok");
          await load();
        } finally {
          buttons.forEach(function (b) {
            b.disabled = false;
          });
        }
      });
    });
    await load();
  }

  // ------------------------------------------------------------ devices

  async function renderDevices(s) {
    var out = status();
    var list = el("ul", { class: "rows" });
    var all = el("button", { type: "button", class: "danger" }, "Sign out everywhere");
    s.append(list, el("div", { class: "actions" }, all), out);
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
        var end = el("button", { type: "button", class: "secondary sm" }, d.current ? "Sign out" : "Sign out this device");
        end.addEventListener("click", function () {
          act(end, out, async function () {
            await api("DELETE", "/v1/me/sessions/" + encodeURIComponent(d.id));
            if (d.current) location.assign("/login");
            else await load();
          });
        });
        var mobile = /Mobi|iPhone|iPad|Android/.test(d.user_agent || "");
        list.append(
          row({
            icon: d.client ? "apps" : mobile ? "phone" : "monitor",
            title: d.client ? "App: " + d.client : deviceName(d.user_agent),
            tooltip: d.client ? null : d.user_agent,
            tags: d.current ? tag("This device", "accent") : null,
            detail: "Signed in " + when(d.created_at) + " · last seen " + when(d.last_seen_at) + (d.ip ? " · " + d.ip : ""),
            action: end,
          }),
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
    if (accessItems.length === 0) list.append(blank("You don't have access to any service yet."));
    accessItems.forEach(function (a) {
      list.append(row({ icon: "apps", title: a.service, tags: tag(a.role), detail: "Since " + when(a.granted_at) }));
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
    s.append(list);
    async function load() {
      var data = await api("GET", "/v1/me/" + kind);
      clear(list);
      if (data.items.length === 0) list.append(blank(isApw ? "No app passwords." : "No API keys."));
      data.items.forEach(function (c) {
        var rm = el("button", { type: "button", class: "danger sm", "data-resume": kind + "-revoke:" + c.id }, "Revoke");
        rm.addEventListener("click", function () {
          if (!confirm("Revoke " + c.name + "? Anything using it stops working.")) return;
          act(rm, out, async function () {
            await api("DELETE", "/v1/me/" + kind + "/" + encodeURIComponent(c.id));
            await load();
          });
        });
        var meta = "Created " + when(c.created_at) + " · last used " + when(c.last_used_at);
        if (!isApw) meta += c.expires_at ? " · expires " + when(c.expires_at) : " · no expiry";
        list.append(
          row({
            icon: isApw ? "lock" : "key",
            title: c.name,
            tags: isApw ? null : el("code", { class: "hint" }, c.id),
            extra: el(
              "span",
              { class: "tags" },
              tag(c.service, "accent"),
              c.scopes.map(function (sc) {
                return tag(sc);
              }),
            ),
            detail: meta,
            action: rm,
          }),
        );
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
    var form = el(
      "form",
      { class: "box-body narrow", "data-resume": kind },
      el("label", {}, "Name", name),
      el("label", {}, "Service", service),
      scopes,
      isApw ? null : el("label", {}, "Expires (optional)", expires),
      create,
      out,
    );
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
    s.append(
      el("div", { class: "box" }, el("div", { class: "box-header" }, el("h3", { class: "box-title" }, isApw ? "New app password" : "New API key")), form),
    );
    return load();
  }

  // ------------------------------------------------------------- delete

  function renderDelete(s) {
    var out = status();
    var del = el("button", { type: "button", class: "danger", "data-resume": "delete" }, "Delete my account");
    del.addEventListener("click", function () {
      if (!confirm("Delete your account? This can't be undone, and every service is told to delete or anonymise your data.")) return;
      act(del, out, async function () {
        await api("DELETE", "/v1/me");
        location.assign("/login");
      });
    });
    s.append(
      el(
        "section",
        { id: "delete", class: "zone", "aria-labelledby": "delete-title" },
        el("h2", { id: "delete-title", class: "danger" }, "Delete account"),
        el(
          "div",
          { class: "box danger" },
          el(
            "div",
            { class: "box-row" },
            el(
              "div",
              { class: "row-main" },
              el("div", { class: "row-title" }, "Delete this account"),
              el("p", { class: "hint" }, "Deletes your account and signs you out everywhere. Every service is told to delete or anonymise your data."),
            ),
            del,
          ),
        ),
        out,
      ),
    );
  }

  // ------------------------------------------------------------- render

  async function render() {
    clear(root);
    var admin = document.getElementById("admin-link");
    if (admin) admin.hidden = !me.admin;
    var nav = el(
      "nav",
      { class: "side-nav", "aria-label": "Account settings" },
      PANES.map(function (p) {
        return el("a", { href: "#" + p[0] }, icon(p[2]), p[1]);
      }),
    );
    panes = el("div", { class: "panes" });
    root.append(pageHead(), el("div", { class: "settings" }, nav, panes));

    var profile = section("profile", "Profile");
    renderProfile(profile);
    if (me.account_deletion) renderDelete(profile);
    var sec = section("security", "Password and authentication");
    renderPassword(sec);
    var tfa = el("div", { class: "box" });
    sec.append(el("h3", {}, "Two-factor authentication"), tfa);
    renderTotp(tfa);
    renderRecovery(tfa);
    var pk = slot(sec);
    var devices = section("devices", "Signed-in devices", "These devices are signed in to your account. Sign out any you don't recognize.");
    var access = section("access", "Your services", "The services you can use, and your role on each.");
    var apw = section(
      "app-passwords",
      "App passwords",
      "For mail, calendar and other apps that can only take a password. Each works for one service and the scopes you choose.",
    );
    var keys = section("api-keys", "API keys", "For scripts and tools that call a service's API.");
    showPane();
    var fail = function (where) {
      return function (e) {
        if (e instanceof ApiError && e.status === 401) return;
        where.append(flash("error", (e && e.message) || "Couldn't load this."));
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
    var noted = takeNoted();
    try {
      await reload();
      if (location.hash) {
        var target = document.getElementById(location.hash.slice(1));
        if (target && !target.classList.contains("pane")) target.scrollIntoView();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return;
      clear(root);
      root.append(flash("error", (e && e.message) || "Couldn't load your account."));
      return;
    }
    carryOn(noted);
  })();
})();
