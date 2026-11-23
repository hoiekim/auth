// Services (docs/DESIGN.md §6, §6.2): which services exist, their roles,
// sign-up policy, scopes, clients and event URL. They come from the services
// file, read once at start, where a rule broken stops the start with every
// problem listed, and from the database, where the same rules refuse a
// registration (registry.ts).

export type Signup = "closed" | "invite" | "open";
export type ServiceSource = "builtin" | "file" | "database";

export interface Client {
  id: string;
  type: "confidential" | "public";
  service: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
}

export interface Service {
  name: string;
  roles: string[];
  mfaRoles: string[];
  signup: Signup;
  defaultRole: string | null;
  managesOwnMembers: boolean;
  apiKeyScopes: string[];
  appPasswordScopes: string[];
  clients: Client[];
  eventsUrl: string | null;
  source: ServiceSource;
}

// auth's own service: its one role manages every service and reads the audit
// log, and always requires MFA (§6).
export const AUTH_SERVICE = "auth";
const AUTH: Service = {
  name: AUTH_SERVICE,
  roles: ["admin"],
  mfaRoles: ["admin"],
  signup: "closed",
  defaultRole: null,
  managesOwnMembers: false,
  apiKeyScopes: [],
  appPasswordScopes: [],
  clients: [],
  eventsUrl: null,
  source: "builtin",
};

// One set of services, as a request sees it from start to end. `held` are
// the database's services that the file overrides (§6.2): listed, not used.
export class Services {
  readonly #byName: Map<string, Service>;
  readonly #clients: Map<string, Client>;
  readonly held: readonly Service[];

  constructor(services: Service[], held: Service[] = []) {
    this.#byName = new Map([AUTH, ...services].map((s) => [s.name, s]));
    this.#clients = new Map(services.flatMap((s) => s.clients.map((c) => [c.id, c] as const)));
    this.held = held;
  }

  get(name: string): Service | undefined {
    return this.#byName.get(name);
  }

  client(id: string): Client | undefined {
    return this.#clients.get(id);
  }

  all(): Service[] {
    return [...this.#byName.values()];
  }

  // The service's role order, lowest first, as declared.
  rank(service: Service, role: string): number {
    return service.roles.indexOf(role);
  }

  requiresMfa(service: Service, role: string): boolean {
    return service.mfaRoles.includes(role);
  }

  anyOpen(): boolean {
    return this.all().some((s) => s.signup === "open");
  }

  // Where a sign-in form's redirects may lead: CSP form-action covers the
  // redirects that follow a form post (§9.2).
  formActionSources(): string[] {
    const sources = new Set<string>();
    for (const client of this.#clients.values()) {
      for (const uri of client.redirectUris) {
        const url = new URL(uri);
        sources.add(url.protocol === "https:" || url.protocol === "http:" ? url.origin : url.protocol);
      }
    }
    return [...sources].sort();
  }
}

const SERVICE_FIELDS = new Set([
  "name",
  "roles",
  "mfa_roles",
  "signup",
  "default_role",
  "manages_own_members",
  "api_key_scopes",
  "app_password_scopes",
  "clients",
  "events_url",
]);
const CLIENT_FIELDS = new Set(["id", "type", "redirect_uris", "post_logout_redirect_uris"]);

const SERVICE_NAME = /^[a-z][a-z0-9-]{0,62}$/;
const ROLE = /^[a-z][a-z0-9_-]{0,31}$/;
const SCOPE = /^[a-z][a-z0-9:._-]{0,63}$/;
const CLIENT_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
// RFC 8252 §7.1: a reverse domain name with at least one dot.
const PRIVATE_SCHEME = /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/;

export function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function parseServices(text: string): { services: Services; problems: string[] } {
  const problems: string[] = [];
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { services: new Services([]), problems: ["the services file is not valid JSON"] };
  }
  if (!isObject(doc) || !Array.isArray(doc.services)) {
    return { services: new Services([]), problems: ['the services file must be an object with a "services" array'] };
  }
  for (const key of Object.keys(doc)) if (key !== "services") problems.push(`the services file has an unknown field "${key}"`);

  const services: Service[] = [];
  const names = new Set<string>();
  const clientIds = new Set<string>();
  doc.services.forEach((raw: unknown, i: number) => {
    const at = isObject(raw) && typeof raw.name === "string" ? `service "${raw.name}"` : `services[${i}]`;
    const parsed = parseService(raw, "file");
    for (const msg of parsed.problems) problems.push(`${at}: ${msg}`);
    const s = parsed.service;
    if (names.has(s.name)) problems.push(`${at}: name is used by another service`);
    names.add(s.name);
    s.clients.forEach((c, j) => {
      if (clientIds.has(c.id)) problems.push(`${at}: clients[${j}]: id "${c.id}" is used by another client`);
      clientIds.add(c.id);
    });
    services.push(s);
  });

  return { services: new Services(services), problems };
}

// A registration's limits (§6), so every copy can hold every service.
export const REGISTRATION_LIMITS = { names: 32, clients: 5, uris: 10, uriLength: 1024 };

// One service in the shape of §6, from the file or a registration's body.
// Every problem is listed; rules across services (unique names and client
// ids) are the caller's. A registration may write [] or null for a field the
// file leaves out, as GET /v1/services answers, and is capped.
export function parseService(raw: unknown, source: "file" | "database"): { service: Service; problems: string[] } {
  const problems: string[] = [];
  const p = (msg: string) => problems.push(msg);
  const registered = source === "database";
  const absent = (v: unknown) => v === undefined || (registered && v === null);
  if (!isObject(raw)) {
    p("must be an object");
    raw = {};
  }
  const r = raw as Record<string, any>;
  for (const key of Object.keys(r)) if (!SERVICE_FIELDS.has(key)) p(`unknown field "${key}"`);

  const name = typeof r.name === "string" ? r.name : "";
  if (!SERVICE_NAME.test(name)) p("name must match [a-z][a-z0-9-]{0,62}");
  else if (name === AUTH_SERVICE) p(`the name "${AUTH_SERVICE}" is reserved`);

  const roles = stringList(r.roles, ROLE, "roles", p, { required: true, nonEmpty: true });
  const mfaRoles = stringList(r.mfa_roles, ROLE, "mfa_roles", p, { required: true, nonEmpty: false });
  for (const role of mfaRoles) if (!roles.includes(role)) p(`mfa_roles has "${role}", which is not one of roles`);

  const signup = r.signup;
  if (signup !== "closed" && signup !== "invite" && signup !== "open") p('signup must be "closed", "invite" or "open"');
  let defaultRole: string | null = null;
  if (signup === "open") {
    if (typeof r.default_role !== "string" || !roles.includes(r.default_role)) p("default_role must be one of roles when signup is open");
    else defaultRole = r.default_role;
  } else if (!absent(r.default_role)) {
    p('default_role is only for signup "open"');
  }

  if (r.manages_own_members !== undefined && typeof r.manages_own_members !== "boolean") p("manages_own_members must be true or false");
  const apiKeyScopes = stringList(r.api_key_scopes, SCOPE, "api_key_scopes", p, { required: false, nonEmpty: !registered });
  const appPasswordScopes = stringList(r.app_password_scopes, SCOPE, "app_password_scopes", p, { required: false, nonEmpty: !registered });
  if (registered) {
    const L = REGISTRATION_LIMITS;
    for (const [field, list] of [["roles", roles], ["api_key_scopes", apiKeyScopes], ["app_password_scopes", appPasswordScopes]] as const) {
      if (list.length > L.names) p(`${field} has more than ${L.names} names`);
    }
    if (Array.isArray(r.clients) && r.clients.length > L.clients) p(`clients has more than ${L.clients}`);
  }

  const clients: Client[] = [];
  const ids = new Set<string>();
  if (!Array.isArray(r.clients) || r.clients.length === 0) p("clients must be a non-empty array");
  else {
    r.clients.forEach((c: unknown, j: number) => {
      const cp = (msg: string) => p(`clients[${j}]: ${msg}`);
      if (!isObject(c)) return cp("must be an object");
      for (const key of Object.keys(c)) if (!CLIENT_FIELDS.has(key)) cp(`unknown field "${key}"`);
      const id = typeof c.id === "string" ? c.id : "";
      if (!CLIENT_ID.test(id)) cp("id must match [a-z0-9][a-z0-9._-]{0,63}");
      else if (ids.has(id)) cp(`id "${id}" is used by another client`);
      ids.add(id);
      const type = c.type;
      if (type !== "confidential" && type !== "public") cp('type must be "confidential" or "public"');
      const isPublic = type === "public";
      const redirectUris = uriList(c.redirect_uris, isPublic, "redirect_uris", cp, true);
      const postLogout = uriList(c.post_logout_redirect_uris, isPublic, "post_logout_redirect_uris", cp, false);
      if (registered) {
        const L = REGISTRATION_LIMITS;
        for (const [field, list] of [["redirect_uris", redirectUris], ["post_logout_redirect_uris", postLogout]] as const) {
          if (list.length > L.uris) cp(`${field} has more than ${L.uris} URIs`);
          if (list.some((u) => u.length > L.uriLength)) cp(`${field} has a URI longer than ${L.uriLength} characters`);
        }
      }
      clients.push({
        id,
        type: isPublic ? "public" : "confidential",
        service: name,
        redirectUris,
        postLogoutRedirectUris: postLogout,
      });
    });
  }

  let eventsUrl: string | null = null;
  if (!absent(r.events_url)) {
    const url = typeof r.events_url === "string" ? parseUrl(r.events_url) : null;
    if (!url || (url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password || url.hash) {
      p("events_url must be an http(s) URL without credentials or a fragment");
    } else if (registered && r.events_url.length > REGISTRATION_LIMITS.uriLength) {
      p(`events_url is longer than ${REGISTRATION_LIMITS.uriLength} characters`);
    } else eventsUrl = r.events_url;
  }

  return {
    service: {
      name,
      roles,
      mfaRoles,
      signup: signup === "open" || signup === "invite" ? signup : "closed",
      defaultRole,
      managesOwnMembers: r.manages_own_members === true,
      apiKeyScopes,
      appPasswordScopes,
      clients,
      eventsUrl,
      source,
    },
    problems,
  };
}

// The shape of §6, as the management API answers with it.
export function serviceJson(s: Service, secrets: ReadonlyMap<string, Date[]> = new Map()) {
  return {
    name: s.name,
    roles: s.roles,
    mfa_roles: s.mfaRoles,
    signup: s.signup,
    default_role: s.defaultRole,
    manages_own_members: s.managesOwnMembers,
    api_key_scopes: s.apiKeyScopes,
    app_password_scopes: s.appPasswordScopes,
    clients: s.clients.map((c) => ({
      id: c.id,
      type: c.type,
      redirect_uris: c.redirectUris,
      post_logout_redirect_uris: c.postLogoutRedirectUris,
      ...(c.type === "confidential" ? { secrets: (secrets.get(c.id) ?? []).map((at) => ({ created_at: at.toISOString() })) } : {}),
    })),
    events_url: s.eventsUrl,
    source: s.source,
  };
}

function isObject(v: unknown): v is Record<string, any> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// A problem names a bad value as JSON, unless it nests deeper than any
// definition does: JSON.stringify recurses, and a services file can nest
// millions of levels deep. The Rust server draws the same line.
const SHOWN_DEPTH = 64;
const TOO_DEEP = `an entry nested more than ${SHOWN_DEPTH} levels deep`;

function nestsDeeper(value: unknown, limit = SHOWN_DEPTH): boolean {
  const pending: [unknown, number][] = [[value, 1]];
  while (pending.length > 0) {
    const [v, depth] = pending.pop()!;
    if (typeof v !== "object" || v === null) continue;
    if (depth > limit) return true;
    for (const child of Array.isArray(v) ? v : Object.values(v)) pending.push([child, depth + 1]);
  }
  return false;
}

function stringList(
  value: unknown,
  pattern: RegExp,
  field: string,
  p: (msg: string) => void,
  opts: { required: boolean; nonEmpty: boolean },
): string[] {
  if (value === undefined && !opts.required) return [];
  if (!Array.isArray(value) || (opts.nonEmpty && value.length === 0)) {
    p(`${field} must be ${opts.nonEmpty ? "a non-empty" : "an"} array of names`);
    return [];
  }
  const out: string[] = [];
  for (const v of value) {
    if (typeof v !== "string" || !pattern.test(v)) p(nestsDeeper(v) ? `${field} has ${TOO_DEEP}` : `${field} has an invalid name ${JSON.stringify(v)}`);
    else if (out.includes(v)) p(`${field} lists "${v}" twice`);
    else out.push(v);
  }
  return out;
}

function parseUrl(text: string): URL | null {
  try {
    return new URL(text);
  } catch {
    return null;
  }
}

// Absolute redirect URIs: https, http only for a loopback host, or a
// private-use scheme for a public client (RFC 8252). Compared later by exact
// string, so they're kept as written.
function uriList(value: unknown, isPublic: boolean, field: string, p: (msg: string) => void, required: boolean): string[] {
  if (value === undefined && !required) return [];
  if (!Array.isArray(value) || (required && value.length === 0)) {
    p(`${field} must be a${required ? " non-empty" : "n"} array of URIs`);
    return [];
  }
  const out: string[] = [];
  for (const v of value) {
    const url = typeof v === "string" ? parseUrl(v) : null;
    const ok =
      url !== null &&
      !url.hash &&
      !url.username &&
      !url.password &&
      (url.protocol === "https:" ||
        (url.protocol === "http:" && isLoopbackHost(url.hostname)) ||
        (isPublic && PRIVATE_SCHEME.test(url.protocol)));
    // A URI with credentials in it is named without them.
    const shown = url && (url.username || url.password) ? "a URI with credentials" : nestsDeeper(v) ? TOO_DEEP : JSON.stringify(v);
    if (!ok) p(`${field} has ${shown}, which is not an https URI, an http URI on a loopback host, or (for a public client) a private-use scheme`);
    else out.push(v as string);
  }
  return out;
}
