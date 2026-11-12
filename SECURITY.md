# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: the
**Security** tab of this repository, then **Report a vulnerability**. Don't
open a public issue, pull request or discussion for it.

Include what an attacker can do, the steps or a proof of concept, and the
commit you tested. The conversation continues in the report.

## Scope

`main` is the only supported version. In scope: this service, its tokens and
events as `docs/DESIGN.md` defines them, and `client/auth-client.ts` once it
exists. A vulnerability in an app that integrates with auth, or in a
particular deployment's configuration, belongs to that app's or that
deployment's maintainers.
