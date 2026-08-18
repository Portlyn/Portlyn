# End to end tests

Playwright suite for the Portlyn admin UI. CI runs it on every push and pull
request against a throwaway hub, so these tests are not optional extras.

## What it covers

* password login, wrong password, unknown account, session across a reload
* redirect of an unauthenticated visitor to the login page
* TOTP: enrol, log in with a generated code, disable again, and a wrong code
* passkeys: register with a virtual authenticator and sign in with it
* domains: create, edit the IP allowlist, confirm it survives a reload, delete
* the service wizard opens once a domain exists

## Run it

```bash
go build -o portlyn ./cmd/server          # with the UI in cmd/server/frontend_dist
sh scripts/e2e-hub.sh ./portlyn ./.tmp/e2e
cd frontend
npm run e2e:install
PLAYWRIGHT_BASE_URL=http://localhost:8000 PORTLYN_E2E_LIVE=1 npm run e2e
```

`scripts/e2e-hub.sh` runs `portlyn init` with a localhost domain, ACME off, admin
MFA not enforced and a high auth rate limit, then starts the hub on port 8000.
Those last two settings only exist so the suite can enrol MFA itself and log in
many times in a row.

Without `PORTLYN_E2E_LIVE` only the tests that work against a bare frontend run.

## State

The suite changes the admin password on first run: `portlyn init` writes an
initial password and the setup wizard forces a new one. `e2e/global-setup.ts`
does that once and every test then logs in with `PORTLYN_TEST_ADMIN_PASSWORD_AFTER_SETUP`.
Start from a fresh data directory if a run leaves the instance half configured.

## Adding tests

Still uncovered:

* magic link redirect
* exposure scan trigger and badge update
* audit webhook create and receive
* tunnel bootstrap and config download
* node enrolment against a real agent

Guidelines:

* Do not mock the backend. These tests exist to catch wiring bugs that unit tests cannot see.
* Keep selectors stable. Prefer roles and accessible names over CSS classes. Add
  an `aria-label` to icon-only buttons rather than reaching for a CSS selector.
* Clean up what a test creates, in a `finally` block if the test can fail midway.
* A TOTP code cannot be replayed. Use `unusedTotp` from `e2e/totp.ts`.
