// The deployment's services file (docs/DESIGN.md §6): which services exist,
// their roles, sign-up policy, scopes, clients and event URL. It is read once
// at start; a file that breaks any rule stops the start with every problem
// listed.

export type Signup = "closed" | "invite" | "open";

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
};

export class Services {
  readonly #byName: Map<string, Service>;
  readonly #clients: Map<string, Client>;

  constructor(services: Service[]) {
    this.#byName = new Map([AUTH, ...services].map((s) => [s.name, s]));
    this.#clients = new Map(services.flatMap((s) => s.clients.map((c) => [c.id, c] as const)));
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
    const p = (msg: string) => problems.push(`${at}: ${msg}`);
    if (!isObject(raw)) return p("must be an object");
    for (const key of Object.keys(raw)) if (!SERVICE_FIELDS.has(key)) p(`unknown field "${key}"`);

    const name = typeof raw.name === "string" ? raw.name : "";
    if (!SERVICE_NAME.test(name)) p("name must match [a-z][a-z0-9-]{0,62}");
    else if (name === AUTH_SERVICE) p(`the name "${AUTH_SERVICE}" is reserved`);
    else if (names.has(name)) p("name is used by another service");
    names.add(name);

    const roles = stringList(raw.roles, ROLE, "roles", p, { required: true, nonEmpty: true });
    const mfaRoles = stringList(raw.mfa_roles, ROLE, "mfa_roles", p, { required: true, nonEmpty: false });
    for (const r of mfaRoles) if (!roles.includes(r)) p(`mfa_roles has "${r}", which is not one of roles`);

    const signup = raw.signup;
    if (signup !== "closed" && signup !== "invite" && signup !== "open") p('signup must be "closed", "invite" or "open"');
    let defaultRole: string | null = null;
    if (signup === "open") {
      if (typeof raw.default_role !== "string" || !roles.includes(raw.default_role)) p("default_role must be one of roles when signup is open");
      else defaultRole = raw.default_role;
    } else if (raw.default_role !== undefined) {
      p('default_role is only for signup "open"');
    }

    if (raw.manages_own_members !== undefined && typeof raw.manages_own_members !== "boolean") p("manages_own_members must be true or false");
    const apiKeyScopes = stringList(raw.api_key_scopes, SCOPE, "api_key_scopes", p, { required: false, nonEmpty: true });
    const appPasswordScopes = stringList(raw.app_password_scopes, SCOPE, "app_password_scopes", p, { required: false, nonEmpty: true });

    const clients: Client[] = [];
    if (!Array.isArray(raw.clients) || raw.clients.length === 0) p("clients must be a non-empty array");
    else {
      raw.clients.forEach((c: unknown, j: number) => {
        const cp = (msg: string) => p(`clients[${j}]: ${msg}`);
        if (!isObject(c)) return cp("must be an object");
        for (const key of Object.keys(c)) if (!CLIENT_FIELDS.has(key)) cp(`unknown field "${key}"`);
        const id = typeof c.id === "string" ? c.id : "";
        if (!CLIENT_ID.test(id)) cp("id must match [a-z0-9][a-z0-9._-]{0,63}");
        else if (clientIds.has(id)) cp(`id "${id}" is used by another client`);
        clientIds.add(id);
        const type = c.type;
        if (type !== "confidential" && type !== "public") cp('type must be "confidential" or "public"');
        const isPublic = type === "public";
        const redirectUris = uriList(c.redirect_uris, isPublic, "redirect_uris", cp, true);
        const postLogout = uriList(c.post_logout_redirect_uris, isPublic, "post_logout_redirect_uris", cp, false);
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
    if (raw.events_url !== undefined) {
      const url = typeof raw.events_url === "string" ? parseUrl(raw.events_url) : null;
      if (!url || (url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password || url.hash) {
        p("events_url must be an http(s) URL without credentials or a fragment");
      } else eventsUrl = raw.events_url;
    }

    services.push({
      name,
      roles,
      mfaRoles,
      signup: signup === "open" || signup === "invite" ? signup : "closed",
      defaultRole,
      managesOwnMembers: raw.manages_own_members === true,
      apiKeyScopes,
      appPasswordScopes,
      clients,
      eventsUrl,
    });
  });

  return { services: new Services(services), problems };
}

function isObject(v: unknown): v is Record<string, any> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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
    if (typeof v !== "string" || !pattern.test(v)) p(`${field} has an invalid name ${JSON.stringify(v)}`);
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
    const shown = url && (url.username || url.password) ? "a URI with credentials" : JSON.stringify(v);
    if (!ok) p(`${field} has ${shown}, which is not an https URI, an http URI on a loopback host, or (for a public client) a private-use scheme`);
    else out.push(v as string);
  }
  return out;
}
