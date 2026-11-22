// What the Bun server's SQL client makes of a DATABASE_URL, recorded for the
// Rust server's tests (rust/src/pgurl.rs), which read each case the same way.
//
//   bun rust/tests/database_urls.ts           rewrites database_urls.json
//   bun rust/tests/database_urls.ts --check   fails if Bun now reads one differently
//
// Each case runs `new SQL(url, { max: 5 })`, as src/db.ts does, with only the
// environment given; `.options` holds what Bun will connect with.
import { SQL } from "bun";

type Env = Record<string, string>;
const cases: [string, Env?][] = [
  ["postgres://auth:s3cret-pw@db.internal:5432/auth"],
  ["postgresql://auth@db.internal/auth"],
  ["postgres://auth:auth@localhost:5432/auth?options=-c%20search_path%3Dc_0123456789ab"],
  ["postgres://db.internal", {}],
  ["postgres://db.internal", { USER: "alice" }],
  ["postgres://db.internal", { USERNAME: "alice" }],
  ["postgres://db.internal", { USER: "alice", PGUSER: "bob", PGUSERNAME: "carol" }],
  ["postgres://db.internal", { USER: "alice", PGUSER: "bob", PG_USER: "dave" }],
  ["postgres://erin@db.internal", { PGUSERNAME: "carol" }],
  ["postgres:///auth", { PGHOST: "db.internal", PGPORT: "6543", PGPASSWORD: "s3cret-pw" }],
  ["postgres:///auth", { PG_HOST: "a.internal", PGHOST: "b.internal" }],
  ["postgres://auth@db.internal/auth", { PGDATABASE: "other" }],
  ["postgres://auth@db.internal/auth?dbname=fromquery", { PGDATABASE: "other" }],
  ["postgres://auth@db.internal/auth?dbname=fromquery"],
  ["postgres://auth:@db.internal/auth", { PGPASSWORD: "from-env" }],
  ["postgres://auth:inline@db.internal/auth", { PGPASSWORD: "from-env" }],
  ["postgres://auth@db.internal/auth", { PGPORT: "abc" }],
  ["postgres://auth@db.internal/auth", { PGPORT: " 6543 " }],
  ["postgres://auth@db.internal:7000/auth", { PGPORT: "6543" }],
  ["postgres://auth:p%40ss%20w@db.internal/my%20db"],
  ["postgres://al%69ce@db.internal/auth"],
  ["postgres://auth:%zz@db.internal/auth"],
  ["postgres://auth:%ff@db.internal/auth"],
  ["postgres://auth@db.internal/a%zz"],
  ["postgres://a%zz@db.internal/auth?user=bob"],
  ["postgres://auth@db.internal/a/b"],
  ["postgres://auth@db.internal/"],
  ["postgres://auth:pw@db.internal:notaport/auth"],
  ["postgresql://auth:pw@db.internal:99999/auth"],
  ["postgres://auth@db.internal:0/auth"],
  ["postgres://auth@db.internal:65535/auth"],
  ["postgres://auth:pw@/auth?host=db.internal&port=6000"],
  ["postgres://:6000/auth"],
  ["postgres://auth@:6000/auth"],
  ["postgres:///auth"],
  ["postgres://auth@[::1]:5433/auth"],
  ["postgres://auth@[fe80::1%25eth0]/auth"],
  ["postgres://auth@a.internal:1,b.internal:2/auth"],
  ["postgres://auth@DB.Internal/auth"],
  ["postgres://auth@db%2Dx.internal/auth"],
  ["postgres://auth@dé.internal/auth"],
  ["postgres://auth@db.inte\trnal/auth"],
  ["postgres://auth@%2Fvar%2Frun%2Fpostgresql/auth"],
  ["postgres://auth@%2fvar%2frun%2fpostgresql:6000/auth"],
  ["postgres://auth@%2F%zz/auth"],
  ["postgres://auth@db.internal/auth?host=/var/run/postgresql"],
  ["postgres://auth@db.internal:6000/auth?host=/var/run/postgresql"],
  ["postgres://auth@db.internal/auth?socket=/tmp"],
  ["postgres://auth@db.internal/auth?path=/run/postgresql/.s.PGSQL.6000"],
  ["postgres://auth@db.internal/auth?path=/nonexistent/socket"],
  ["postgres://auth@db.internal/auth?host=/var/run/postgresql&sslmode=require"],
  ["postgres://auth@db.internal/auth?path="],
  ["postgres://auth@db.internal/auth?sslmode=disable"],
  ["postgres://auth@db.internal/auth?sslmode=DISABLED"],
  ["postgres://auth@db.internal/auth?sslmode=allow"],
  ["postgres://auth@db.internal/auth?sslmode=prefer"],
  ["postgres://auth@db.internal/auth?sslmode=preferred"],
  ["postgres://auth@db.internal/auth?sslmode=require"],
  ["postgres://auth@db.internal/auth?sslmode=Required"],
  ["postgres://auth@db.internal/auth?sslmode=verify-ca"],
  ["postgres://auth@db.internal/auth?sslmode=verify_ca"],
  ["postgres://auth@db.internal/auth?sslmode=verify-full"],
  ["postgres://auth@db.internal/auth?sslmode=verify_identity"],
  ["postgres://auth@db.internal/auth?sslmode=bogus"],
  ["postgres://auth@db.internal/auth?sslmode=no-verify"],
  ["postgres://auth@db.internal/auth?sslmode="],
  ["postgres://auth@db.internal/auth?sslmode"],
  ["postgres://auth@db.internal/auth?sslmode=disable&sslmode=require"],
  ["postgres://auth@db.internal/auth?SSLMODE=require"],
  ["postgres://auth@db.internal/auth?ssl-mode=require"],
  ["postgres://auth@db.internal/auth?ssl_mode=verify-full"],
  ["postgres://auth@db.internal/auth?ssl%6Dode=require"],
  ["postgres://auth@db.internal/auth?ssl=true"],
  ["postgres://auth@db.internal/auth?ssl=1"],
  ["postgres://auth@db.internal/auth?tls=TRUE"],
  ["postgres://auth@db.internal/auth?ssl=false"],
  ["postgres://auth@db.internal/auth?tls=0"],
  ["postgres://auth@db.internal/auth?ssl=require"],
  ["postgres://auth@db.internal/auth?tls=verify-full"],
  ["postgres://auth@db.internal/auth?ssl=maybe"],
  ["postgres://auth@db.internal/auth?ssl="],
  ["postgres://auth@db.internal/auth?sslmode=prefer&ssl=true"],
  ["postgres://auth@db.internal/auth?sslmode=verify-ca&ssl=true"],
  ["postgres://auth@db.internal/auth?ssl=false&sslmode=require"],
  ["postgres://auth@db.internal/auth", { PGSSLMODE: "verify-ca" }],
  ["postgres://auth@db.internal/auth?sslmode=disable", { PGSSLMODE: "require" }],
  ["postgres://auth@db.internal/auth", { PGSSLMODE: "bogus" }],
  ["postgres://auth@db.internal/auth?sslmode=require", { PGSSLMODE: "bogus" }],
  ["postgres://auth@db.internal/auth", { PG_SSLMODE: "prefer", PGSSLMODE: "verify-full" }],
  ["postgres://auth@db.internal/auth?sslrootcert=/etc/ssl/db-ca.pem"],
  ["postgres://auth@db.internal/auth?sslmode=require&sslrootcert=/etc/ssl/db-ca.pem"],
  ["postgres://auth@db.internal/auth?sslmode=prefer&sslrootcert=/etc/ssl/db-ca.pem"],
  ["postgres://auth@db.internal/auth?sslmode=verify-ca&sslrootcert=/etc/ssl/db-ca.pem"],
  ["postgres://auth@db.internal/auth?sslmode=disable&sslrootcert=/etc/ssl/db-ca.pem"],
  ["postgres://auth@db.internal/auth?sslmode=require&sslrootcert=system"],
  ["postgres://auth@db.internal/auth?sslmode=verify-ca&sslrootcert=system"],
  ["postgres://auth@db.internal/auth?sslrootcert=system&SSLROOTCERT=/etc/ssl/db-ca.pem"],
  ["postgres://auth@db.internal/auth?sslrootcert=/a.pem&SSLROOTCERT=/b.pem"],
  ["postgres://auth@db.internal/auth?sslrootcert="],
  ["postgres://auth@db.internal/auth?ssl=false&sslcert=/etc/ssl/client.pem"],
  ["postgres://auth@db.internal/auth?sslcert=/etc/ssl/client.pem&sslkey=/etc/ssl/client.key&sslpassword=s3cret-pw"],
  ["postgres://auth@db.internal/auth?sslmode=verify-full&sslkey=/etc/ssl/client.key"],
  ["postgres://auth@db.internal/auth?application_name=wiki-auth"],
  ["postgres://auth@db.internal/auth?application_name=a&application_name=b"],
  ["postgres://auth@db.internal/auth?application_name=a+b&search_path=s1"],
  ["postgres://auth@db.internal/auth?application_name=%zz"],
  ["postgres://auth@db.internal/auth?application_name="],
  ["postgres://auth@db.internal/auth?application_name=x", { PGAPPNAME: "from-env", PGOPTIONS: "-c work_mem=4MB" }],
  ["postgres://auth@db.internal/auth?statement_timeout=5&application_name=x", { PGAPPNAME: "from-env" }],
  ["postgres://auth@db.internal/auth?options=-c%20statement_timeout%3D777&statement_timeout=888"],
  ["postgres://auth@db.internal/auth?Statement_Timeout=999&foo=bar"],
  ["postgres://auth@db.internal/auth?database=other"],
  ["postgres://auth@db.internal/auth?Database=other"],
  ["postgres://auth@db.internal/auth?DBNAME=other&USER=bob&Password=pw&HOST=h.internal&Port=6000"],
  ["postgres://auth@db.internal/auth?gssencmode=require"],
  ["postgres://auth@db.internal/auth?gssencmode=disable"],
  ["postgres://auth@db.internal/auth?keepalives=1&keepalives_idle=5&keepalives_interval=1&keepalives_count=3&tcp_user_timeout=9&target_session_attrs=read-write&load_balance_hosts=random&fallback_application_name=x&sslnegotiation=direct&sslcompression=0"],
  ["postgres://auth@db.internal/auth?a"],
  ["postgres://auth@db.internal/auth?=x"],
  ["postgres://auth@db.internal/auth?application_name=%00"],
  ["postgres://auth@db.internal/auth?%00x=1"],
  ["postgres://auth@db.internal/auth#fragment"],
  ["postgres://auth@db.internal/auth?connect_timeout=10"],
  ["postgres://auth@db.internal/auth?connect_timeout=1.5"],
  ["postgres://auth@db.internal/auth?connect_timeout=0"],
  ["postgres://auth@db.internal/auth?connect_timeout=-1"],
  ["postgres://auth@db.internal/auth?connect_timeout=abc"],
  ["postgres://auth@db.internal/auth?connect_timeout=2147483648"],
  ["postgres://auth@db.internal/auth?connect_timeout=2147483649"],
  ["postgres://auth@db.internal/auth?connect_timeout=0x10"],
  ["postgres://auth@db.internal/auth?connect_timeout=%201e1%20"],
  ["postgres://auth@db.internal/auth?connect_timeout="],
  ["postgres://auth@db.internal/auth", { PGCONNECT_TIMEOUT: "7" }],
  ["postgres://auth@db.internal/auth?connect_timeout=3", { PGCONNECT_TIMEOUT: "7" }],
  ["postgres://auth@db.internal/auth", { PGCONNECT_TIMEOUT: "never" }],
  ["postgres://auth@db.internal/auth?idle_timeout=5&max_lifetime=60"],
  ["postgres://auth@db.internal/auth?idle_timeout=-0"],
  ["postgres://auth@db.internal/auth?max_lifetime=Infinity"],
  ["postgres://auth@db.internal/auth?max=abc&foundrows=true"],
  ["postgres://auth@db.internal/auth?prepare=false"],
  ["postgres://auth@db.internal/auth?prepare=0"],
  ["postgres://auth@db.internal/auth?prepare=true"],
  ["postgres://auth@db.internal/auth?prepare=no"],
  ["postgres://auth@db.internal/auth?channel_binding=require"],
  ["postgres://auth@db.internal/auth?channel_binding=prefer"],
  ["postgres://auth@db.internal/auth?channel_binding=disable"],
  ["postgres://auth@db.internal/auth?channel_binding=sometimes"],
  ["postgres://auth@db.internal/auth?channel_binding=REQUIRE"],
  ["postgres://auth@db.internal/auth", { PGCHANNELBINDING: "require" }],
  ["postgres://auth@db.internal/auth", { PGCHANNELBINDING: "always" }],
  ["postgres://auth@db.internal/auth?host=other.internal&port=6000&user=bob&password=pw2&dbname=db2"],
  ["postgres://auth@db.internal/auth?port=0x1770"],
  ["postgres://auth@db.internal/auth?port=5e3"],
  ["postgres://auth@db.internal/auth?port=1.5"],
  ["postgres://auth@db.internal/auth?port=0"],
  ["postgres://auth@db.internal/auth?port=70000"],
  ["postgres://auth@db.internal/auth?port="],
  ["postgres://auth@db.internal/auth?port=6000&PORT=7000"],
  ["postgres://auth@db.internal/auth?host=&user="],
];

const CLEARED = /^(PG|PG_)|^(USER|USERNAME)$/;

function bunReads(url: string, env: Env): unknown {
  for (const name of Object.keys(process.env)) if (CLEARED.test(name)) delete process.env[name];
  Object.assign(process.env, env);
  let o: Record<string, any>;
  try {
    o = (new SQL(url, { max: 5 }) as unknown as { options: Record<string, any> }).options;
  } catch {
    return { refused: true };
  }
  const startup: [string, string][] = [];
  const parts = String(o.query ?? "").split("\0");
  for (let i = 0; i + 1 < parts.length; i += 2) startup.push([parts[i]!, parts[i + 1]!]);
  let tls: Record<string, unknown> | null = null;
  if (o.sslMode !== 0) {
    tls = {};
    for (const key of ["caFile", "certFile", "keyFile", "passphrase", "rejectUnauthorized", "serverName"]) {
      if (o.tls?.[key] !== undefined) tls[key] = o.tls[key];
    }
  }
  return {
    hostname: o.hostname,
    port: o.port,
    username: o.username,
    password: o.password,
    database: o.database,
    path: o.path ?? null,
    sslMode: o.sslMode,
    tls,
    startup,
    channelBinding: o.channelBinding,
    prepare: o.prepare,
    connectionTimeout: o.connectionTimeout ?? null,
    idleTimeout: o.idleTimeout ?? null,
    maxLifetime: o.maxLifetime ?? null,
  };
}

const file = new URL("database_urls.json", import.meta.url).pathname;
const recorded = cases.map(([url, env = {}]) => ({ url, env, bun: bunReads(url, env) }));
const text = `${JSON.stringify(recorded, null, 1)}\n`;
if (process.argv.includes("--check")) {
  if ((await Bun.file(file).text()) !== text) {
    console.error(`Bun ${Bun.version} reads a DATABASE_URL differently from ${file}: rerun without --check, then make rust/src/pgurl.rs agree`);
    process.exit(1);
  }
  console.log(`${recorded.length} cases read as recorded`);
} else {
  await Bun.write(file, text);
  console.log(`recorded ${recorded.length} cases in ${file}`);
}
