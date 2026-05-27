# End to end tests

Playwright suite for the Portlyn admin UI.
The default run is CI safe: it only exercises pages that work without a backend.
Live integration tests are gated behind an explicit environment variable.

## Setup

```bash
cd frontend
npm install
npm run e2e:install
```

`npm run e2e:install` calls `playwright install --with-deps chromium`.

## CI safe run

```bash
cd frontend
npm run dev &
sleep 4
PLAYWRIGHT_BASE_URL=http://localhost:3000 npm run e2e
```

Asserts:

* `/login` renders
* empty form submission stays on `/login`

## Live integration run

Set `PORTLYN_E2E_LIVE=1` and provide credentials for an account on a live backend.

```bash
export PORTLYN_E2E_LIVE=1
export PORTLYN_TEST_ADMIN_EMAIL=admin@example.test
export PORTLYN_TEST_ADMIN_PASSWORD='your bootstrap password'
export PLAYWRIGHT_BASE_URL=https://portlyn.example.test
npm run e2e
```

## Adding tests

Critical flows to cover next:

* Service wizard create flow
* Magic link redirect
* Exposure scan trigger and badge update
* Audit webhook create and receive (Beeceptor or local echo server)
* Tunnel bootstrap and config download
* Passkey registration (requires a virtual authenticator; see Playwright docs)

Guidelines:

* Do not mock the backend. These tests exist to catch wiring bugs that unit tests cannot see.
* Keep selectors stable. Prefer roles and accessible names over CSS classes.
* Mark live only tests with `test.skip(!process.env.PORTLYN_E2E_LIVE, ...)`.
* Tag flows that mutate state so they can be excluded from production smoke runs.
