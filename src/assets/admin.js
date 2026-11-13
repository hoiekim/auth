(function () {
  "use strict";

  // The admin page: users, access, invitations, services and the audit log,
  // through the same /v1 API apps use.

  var root = document.getElementById("app");
  if (!root) return;
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrf = csrfMeta ? csrfMeta.getAttribute("content") || "" : "";
  var services = [];

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
    if (!iso) return "—";
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
    if (reauth) params.set("reauth", "1");
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

  function status() {
    return el("p", { class: "error", role: "alert", hidden: true });
  }

  function say(node, message, kind) {
    node.className = kind === "ok" ? "notice" : "error";
    node.textContent = message;
    node.hidden = !message;
  }

  async function act(button, out, fn) {
    if (out) say(out, "");
    if (button) button.disabled = true;
    try {
      await fn();
    } catch (e) {
      if (out && !(e instanceof ApiError && (e.status === 401 || e.code === "reauth_required"))) say(out, (e && e.message) || "That didn't work.");
    } finally {
      if (button) button.disabled = false;
    }
  }

  function secretBox(title, value) {
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
      el("p", { class: "hint" }, "Shown only now. Hand it over safely before you leave this page."),
      el("pre", {}, value),
    );
    var done = el("button", { type: "button", class: "secondary" }, "Done");
    done.addEventListener("click", function () {
      box.remove();
    });
    box.append(el("div", { class: "actions" }, copy, done));
    return box;
  }

  function options(values, selected) {
    return values.map(function (v) {
      return el("option", { value: v, selected: v === selected }, v);
    });
  }

  function serviceNamed(name) {
    return services.find(function (s) {
      return s.name === name;
    });
  }

  function table(headers, rows) {
    return el(
      "div",
      { class: "table-wrap" },
      el(
        "table",
        {},
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            headers.map(function (h) {
              return el("th", { scope: "col" }, h);
            }),
          ),
        ),
        el("tbody", {}, rows),
      ),
    );
  }

  // --------------------------------------------------------------- tabs

  var tabs = el("nav", { class: "tabs", "aria-label": "Admin sections" });
  var view = el("div");
  var TABS = [
    ["users", "Users", showUsers],
    ["invites", "Invitations", showInvites],
    ["services", "Services", showServices],
    ["audit", "Audit log", showAudit],
  ];

  function go(name) {
    var tab =
      TABS.find(function (t) {
        return t[0] === name;
      }) || TABS[0];
    Array.prototype.forEach.call(tabs.children, function (b) {
      if (b.dataset.tab === tab[0]) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    if (location.hash !== "#" + tab[0]) history.replaceState(null, "", "#" + tab[0]);
    clear(view);
    tab[2]().catch(function (e) {
      if (e instanceof ApiError && (e.status === 401 || e.code === "reauth_required")) return;
      view.append(el("p", { class: "error", role: "alert" }, (e && e.message) || "Couldn't load this."));
    });
  }

  TABS.forEach(function (t) {
    var b = el("button", { type: "button", "data-tab": t[0] }, t[1]);
    b.addEventListener("click", function () {
      go(t[0]);
    });
    tabs.append(b);
  });

  // -------------------------------------------------------------- users

  async function showUsers() {
    view.append(el("h2", {}, "Users"));
    var q = el("input", { type: "search", placeholder: "Username, name or email", maxlength: "254" });
    var search = el("button", { type: "submit" }, "Search");
    var out = status();
    var list = el("ul", { class: "rows" });
    var more = el("button", { type: "button", class: "secondary", hidden: true }, "More");
    var form = el("form", { class: "inline", role: "search" }, el("label", {}, "Find", q), search);
    var next = null;
    async function load(reset) {
      if (reset) {
        clear(list);
        next = null;
      }
      var params = new URLSearchParams({ q: q.value.trim(), limit: "50" });
      if (next) params.set("after", next);
      var data = await api("GET", "/v1/users?" + params.toString());
      data.items.forEach(function (u) {
        var open = el("button", { type: "button", class: "link" }, u.username);
        open.addEventListener("click", function () {
          showUser(u.id);
        });
        list.append(
          el(
            "li",
            {},
            el(
              "div",
              {},
              open,
              u.kind === "bot" ? el("span", { class: "tag" }, "bot") : null,
              u.disabled ? el("span", { class: "tag" }, "disabled") : null,
              el("p", { class: "hint" }, [u.name, u.email].filter(Boolean).join(" · ")),
            ),
          ),
        );
      });
      if (list.children.length === 0) list.append(el("li", {}, el("span", { class: "muted" }, "No users found.")));
      next = data.next;
      more.hidden = !next;
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(search, out, function () {
        return load(true);
      });
    });
    more.addEventListener("click", function () {
      act(more, out, function () {
        return load(false);
      });
    });
    view.append(form, out, list, more, createUserForm());
    await load(true);
  }

  function createUserForm() {
    var out = status();
    var kind = el("select", {}, el("option", { value: "person" }, "Person"), el("option", { value: "bot" }, "Bot"));
    var username = el("input", { required: true, maxlength: "32", pattern: "[a-z][a-z0-9-]{1,30}[a-z0-9]", autocomplete: "off" });
    var name = el("input", { maxlength: "200", autocomplete: "off" });
    var email = el("input", { type: "email", maxlength: "254", required: true, autocomplete: "off" });
    var owner = el("input", { maxlength: "40", placeholder: "usr_… (default: you)", autocomplete: "off" });
    var emailLabel = el("label", {}, "Email (gets an activation link)", email);
    var ownerLabel = el("label", { hidden: true }, "Owner's user id", owner);
    kind.addEventListener("change", function () {
      var bot = kind.value === "bot";
      emailLabel.hidden = bot;
      email.required = !bot;
      ownerLabel.hidden = !bot;
    });
    var create = el("button", { type: "submit" }, "Create user");
    var form = el(
      "form",
      {},
      el("label", {}, "Kind", kind),
      el("label", {}, "Username", username),
      el("p", { class: "hint" }, "3–32 characters: a–z, 0–9 and '-'. It can never change."),
      el("label", {}, "Name", name),
      emailLabel,
      ownerLabel,
      create,
      out,
    );
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(create, out, async function () {
        var body = { username: username.value.trim(), name: name.value.trim(), kind: kind.value };
        if (kind.value === "person") body.email = email.value.trim();
        else if (owner.value.trim()) body.owner_id = owner.value.trim();
        var u = await api("POST", "/v1/users", body);
        username.value = "";
        name.value = "";
        email.value = "";
        owner.value = "";
        say(out, "Created " + u.username + (u.kind === "person" ? ". An activation link is on its way to " + u.email + "." : "."), "ok");
      });
    });
    return el("details", { class: "panel" }, el("summary", {}, "Create a user"), form);
  }

  async function showUser(id) {
    clear(view);
    var back = el("button", { type: "button", class: "secondary" }, "← All users");
    back.addEventListener("click", function () {
      go("users");
    });
    view.append(back);
    var u = await api("GET", "/v1/users/" + encodeURIComponent(id));
    var out = status();
    var refresh = function () {
      return showUser(id);
    };
    view.append(
      el("h2", {}, u.username, u.kind === "bot" ? el("span", { class: "tag" }, "bot") : null, u.disabled ? el("span", { class: "tag" }, "disabled") : null),
      el(
        "div",
        { class: "panel" },
        el("p", {}, "Id: ", el("code", {}, u.id)),
        el("p", {}, "Name: ", u.name || "—"),
        u.kind === "person" ? el("p", {}, "Email: ", u.email || "—", u.email && !u.email_verified ? " (not confirmed)" : "") : null,
        u.owner_id ? el("p", {}, "Owner: ", el("code", {}, u.owner_id)) : null,
        el("p", {}, "Created: ", when(u.created_at)),
        u.kind === "person"
          ? el(
              "p",
              {},
              "Second factors: ",
              [u.mfa.totp ? "authenticator app" : null, u.mfa.passkeys ? u.mfa.passkeys + " passkey(s)" : null].filter(Boolean).join(", ") || "none",
              " · " + u.mfa.recovery_codes + " recovery code(s) left",
            )
          : null,
      ),
      out,
    );

    // Access
    var rows = u.access.map(function (a) {
      var remove = el("button", { type: "button", class: "danger" }, "Remove");
      remove.addEventListener("click", function () {
        if (!confirm("Remove " + u.username + "'s access to " + a.service + "?")) return;
        act(remove, out, async function () {
          await api("DELETE", "/v1/users/" + encodeURIComponent(u.id) + "/access/" + encodeURIComponent(a.service));
          await refresh();
        });
      });
      return el("tr", {}, el("td", {}, a.service), el("td", {}, a.role), el("td", {}, a.granted_by), el("td", {}, when(a.granted_at)), el("td", {}, remove));
    });
    view.append(el("h3", {}, "Access"), rows.length ? table(["Service", "Role", "Granted by", "Since", ""], rows) : el("p", { class: "muted" }, "No access to any service."));
    var svc = el("select", {}, options(services.map(function (s) {
      return s.name;
    })));
    var role = el("select", {});
    function drawRoles() {
      clear(role);
      var s = serviceNamed(svc.value);
      var current = u.access.find(function (a) {
        return a.service === svc.value;
      });
      append(role, options(s ? s.roles : [], current ? current.role : undefined));
    }
    svc.addEventListener("change", drawRoles);
    drawRoles();
    var grant = el("button", { type: "submit" }, "Grant or change");
    var grantForm = el("form", { class: "inline" }, el("label", {}, "Service", svc), el("label", {}, "Role", role), grant);
    grantForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(grant, out, async function () {
        await api("PUT", "/v1/users/" + encodeURIComponent(u.id) + "/access/" + encodeURIComponent(svc.value), { role: role.value });
        await refresh();
      });
    });
    view.append(grantForm);

    // Account actions
    var actions = el("div", { class: "actions" });
    var toggle = el("button", { type: "button", class: u.disabled ? "secondary" : "danger" }, u.disabled ? "Enable" : "Disable");
    toggle.addEventListener("click", function () {
      if (!u.disabled && !confirm("Disable " + u.username + "? Their sessions, tokens, app passwords and keys stop at once.")) return;
      act(toggle, out, async function () {
        await api("PATCH", "/v1/users/" + encodeURIComponent(u.id), { disabled: !u.disabled });
        await refresh();
      });
    });
    var signout = el("button", { type: "button", class: "secondary" }, "Sign out everywhere");
    signout.addEventListener("click", function () {
      act(signout, out, async function () {
        await api("DELETE", "/v1/users/" + encodeURIComponent(u.id) + "/sessions");
        say(out, u.username + " is signed out everywhere.", "ok");
      });
    });
    var del = el("button", { type: "button", class: "danger" }, "Delete");
    del.addEventListener("click", function () {
      if (!confirm("Delete " + u.username + "? This can't be undone, and every service is told.")) return;
      act(del, out, async function () {
        await api("DELETE", "/v1/users/" + encodeURIComponent(u.id));
        go("users");
      });
    });
    actions.append(toggle, signout, del);
    view.append(el("h3", {}, "Account"), actions);

    if (u.kind === "person") {
      var sendLink = el("input", { type: "checkbox", checked: true });
      var clearMfa = el("input", { type: "checkbox" });
      var reset = el("button", { type: "submit", class: "danger" }, "Reset");
      var resetForm = el(
        "form",
        {},
        el("p", { class: "hint" }, "Only after verifying the person out of band. This is audited and alerted."),
        el("label", { class: "check" }, sendLink, "Email a password reset link"),
        el("label", { class: "check" }, clearMfa, "Clear their second factors (and sign them out)"),
        reset,
      );
      resetForm.addEventListener("submit", function (ev) {
        ev.preventDefault();
        act(reset, out, async function () {
          await api("POST", "/v1/users/" + encodeURIComponent(u.id) + "/reset", { send_link: sendLink.checked, clear_mfa: clearMfa.checked });
          await refresh();
          var o = view.querySelector("[role=alert]");
          if (o) say(o, "Done.", "ok");
        });
      });
      view.append(el("h3", {}, "Reset"), resetForm);
    } else {
      var held = u.access.map(function (a) {
        return a.service;
      });
      view.append(el("h3", {}, "App passwords"));
      await credentialPanel(view, u.id, "app-passwords", held);
      view.append(el("h3", {}, "API keys"));
      await credentialPanel(view, u.id, "api-keys", held);
    }
  }

  async function credentialPanel(parent, userId, kind, held) {
    var isApw = kind === "app-passwords";
    var scopesField = isApw ? "app_password_scopes" : "api_key_scopes";
    var secretField = isApw ? "password" : "key";
    var base = "/v1/users/" + encodeURIComponent(userId) + "/" + kind;
    var usable = services.filter(function (s) {
      return held.indexOf(s.name) >= 0 && s[scopesField].length > 0;
    });
    var box = el("div", { class: "panel" });
    var out = status();
    var list = el("ul", { class: "rows" });
    var created = el("div");
    box.append(created, list);
    parent.append(box);
    async function load() {
      var data = await api("GET", base);
      clear(list);
      if (data.items.length === 0) list.append(el("li", {}, el("span", { class: "muted" }, "None.")));
      data.items.forEach(function (c) {
        var rm = el("button", { type: "button", class: "danger" }, "Revoke");
        rm.addEventListener("click", function () {
          if (!confirm("Revoke " + c.name + "?")) return;
          act(rm, out, async function () {
            await api("DELETE", base + "/" + encodeURIComponent(c.id));
            await load();
          });
        });
        var meta = c.service + " · " + c.scopes.join(", ") + " · last used " + when(c.last_used_at);
        if (!isApw) meta += c.expires_at ? " · expires " + when(c.expires_at) : " · no expiry";
        list.append(el("li", {}, el("div", {}, el("strong", {}, c.name), el("p", { class: "hint" }, meta)), rm));
      });
    }
    if (usable.length === 0) {
      box.append(el("p", { class: "hint" }, "Give this bot a role on a service that takes " + (isApw ? "app passwords" : "API keys") + " first."), out);
      return load();
    }
    var name = el("input", { required: true, maxlength: "100" });
    var svc = el(
      "select",
      {},
      options(
        usable.map(function (s) {
          return s.name;
        }),
      ),
    );
    var scopes = el("fieldset", {});
    function drawScopes() {
      clear(scopes);
      scopes.append(el("legend", {}, "Scopes"));
      var s = serviceNamed(svc.value);
      (s ? s[scopesField] : []).forEach(function (sc) {
        scopes.append(el("label", { class: "check" }, el("input", { type: "checkbox", value: sc, checked: true }), sc));
      });
    }
    svc.addEventListener("change", drawScopes);
    drawScopes();
    var expires = el("input", { type: "date" });
    var create = el("button", { type: "submit" }, isApw ? "Create app password" : "Create API key");
    var form = el("form", {}, el("label", {}, "Name", name), el("label", {}, "Service", svc), scopes, isApw ? null : el("label", {}, "Expires (optional)", expires), create, out);
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(create, out, async function () {
        var picked = Array.prototype.slice.call(scopes.querySelectorAll("input:checked")).map(function (i) {
          return i.value;
        });
        if (picked.length === 0) throw new Error("Choose at least one scope.");
        var body = { name: name.value.trim(), service: svc.value, scopes: picked };
        if (!isApw && expires.value) body.expires_at = expires.value + "T23:59:59Z";
        var c = await api("POST", base, body);
        name.value = "";
        clear(created);
        created.append(secretBox((isApw ? "App password" : "API key") + " for " + c.service + ": " + c.name, c[secretField]));
        await load();
      });
    });
    box.append(form);
    return load();
  }

  // ------------------------------------------------------------ invites

  async function showInvites() {
    view.append(el("h2", {}, "Invitations"));
    var out = status();
    var open = services.filter(function (s) {
      return s.signup !== "closed";
    });
    var email = el("input", { type: "email", required: true, maxlength: "254", autocomplete: "off" });
    var svc = el(
      "select",
      {},
      options(
        open.map(function (s) {
          return s.name;
        }),
      ),
    );
    var role = el("select", {});
    function drawRoles() {
      clear(role);
      var s = serviceNamed(svc.value);
      append(role, options(s ? s.roles : [], s && s.roles[0]));
    }
    svc.addEventListener("change", drawRoles);
    drawRoles();
    var send = el("button", { type: "submit" }, "Send invitation");
    var form = el("form", {}, el("label", {}, "Email", email), el("label", {}, "Service", svc), el("label", {}, "Role", role), send, out);
    var list = el("div");
    var more = el("button", { type: "button", class: "secondary", hidden: true }, "More");
    var rows = [];
    var next = null;
    async function load(reset) {
      if (reset) {
        rows = [];
        next = null;
      }
      var params = new URLSearchParams({ limit: "50" });
      if (next) params.set("after", next);
      var data = await api("GET", "/v1/invites?" + params.toString());
      data.items.forEach(function (i) {
        var del = el("button", { type: "button", class: "danger" }, "Delete");
        del.addEventListener("click", function () {
          if (!confirm("Delete the invitation to " + i.email + "?")) return;
          act(del, out, async function () {
            await api("DELETE", "/v1/invites/" + encodeURIComponent(i.id));
            await load(true);
          });
        });
        rows.push(
          el(
            "tr",
            {},
            el("td", {}, i.email),
            el("td", {}, i.service + ":" + i.role),
            el("td", {}, i.accepted_at ? "accepted " + when(i.accepted_at) : "expires " + when(i.expires_at)),
            el("td", {}, i.accepted_by ? el("code", {}, i.accepted_by) : "—"),
            el("td", {}, del),
          ),
        );
      });
      next = data.next;
      more.hidden = !next;
      clear(list);
      list.append(rows.length ? table(["Email", "Access", "State", "Accepted by", ""], rows) : el("p", { class: "muted" }, "No invitations."));
    }
    if (open.length === 0) form = el("p", { class: "hint" }, "Every service is closed to sign-up, so none takes invitations.");
    else
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        act(send, out, async function () {
          var i = await api("POST", "/v1/invites", { email: email.value.trim(), service: svc.value, role: role.value });
          email.value = "";
          say(out, "Invitation " + i.id + " sent to " + i.email + ".", "ok");
          await load(true);
        });
      });
    more.addEventListener("click", function () {
      act(more, out, function () {
        return load(false);
      });
    });
    view.append(form, el("h3", {}, "Sent"), list, more);
    await load(true);
  }

  // ----------------------------------------------------------- services

  async function showServices() {
    view.append(el("h2", {}, "Services"), el("p", { class: "hint" }, "From the deployment's services file; it changes with a restart."));
    services.forEach(function (s) {
      view.append(
        el(
          "div",
          { class: "panel" },
          el("h3", {}, s.name),
          el("p", {}, "Roles, lowest first: ", s.roles.join(", ")),
          el("p", {}, "Roles that need MFA: ", s.mfa_roles.length ? s.mfa_roles.join(", ") : "none"),
          el("p", {}, "Sign-up: ", s.signup, s.default_role ? " (default role " + s.default_role + ")" : ""),
          s.manages_own_members ? el("p", {}, "Manages its own members.") : null,
          s.app_password_scopes.length ? el("p", {}, "App password scopes: ", s.app_password_scopes.join(", ")) : null,
          s.api_key_scopes.length ? el("p", {}, "API key scopes: ", s.api_key_scopes.join(", ")) : null,
          s.clients.length
            ? el(
                "ul",
                {},
                s.clients.map(function (c) {
                  return el("li", {}, el("code", {}, c.id), " (" + c.type + "): ", c.redirect_uris.join(", "));
                }),
              )
            : null,
          s.events_url ? el("p", {}, "Events: ", el("code", {}, s.events_url)) : null,
        ),
      );
    });
  }

  // -------------------------------------------------------------- audit

  async function showAudit() {
    view.append(el("h2", {}, "Audit log"));
    var user = el("input", { placeholder: "usr_…", maxlength: "40", autocomplete: "off" });
    var filter = el("button", { type: "submit" }, "Filter");
    var out = status();
    var form = el("form", { class: "inline" }, el("label", {}, "User id", user), filter);
    var holder = el("div");
    var more = el("button", { type: "button", class: "secondary", hidden: true }, "More");
    var rows = [];
    var next = null;
    async function load(reset) {
      if (reset) {
        rows = [];
        next = null;
      }
      var params = new URLSearchParams({ limit: "100" });
      if (user.value.trim()) params.set("user", user.value.trim());
      if (next) params.set("after", next);
      var data = await api("GET", "/v1/audit?" + params.toString());
      data.items.forEach(function (r) {
        rows.push(
          el(
            "tr",
            {},
            el("td", {}, when(r.at)),
            el("td", {}, r.action),
            el("td", {}, r.actor ? el("code", {}, r.actor) : "—"),
            el("td", {}, r.user_id ? el("code", {}, r.user_id) : "—"),
            el("td", {}, r.ip || "—"),
            el("td", {}, el("code", {}, JSON.stringify(r.detail))),
          ),
        );
      });
      next = data.next;
      more.hidden = !next;
      clear(holder);
      holder.append(rows.length ? table(["When", "Action", "Actor", "User", "Address", "Detail"], rows) : el("p", { class: "muted" }, "Nothing logged."));
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(filter, out, function () {
        return load(true);
      });
    });
    more.addEventListener("click", function () {
      act(more, out, function () {
        return load(false);
      });
    });
    view.append(form, out, holder, more);
    await load(true);
  }

  // -------------------------------------------------------------- start

  (async function start() {
    clear(root);
    root.append(el("h1", {}, "Administration"), tabs, view);
    try {
      services = (await api("GET", "/v1/services")).items;
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.code === "reauth_required")) return;
      view.append(el("p", { class: "error", role: "alert" }, (e && e.message) || "Couldn't load the services."));
      return;
    }
    go(location.hash.slice(1));
  })();
})();
