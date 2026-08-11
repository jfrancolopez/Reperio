# web — LAN web interface

Owner: the browser UI built later as a React/TypeScript static SPA.

- **Source of truth:** `docs/MASTER_PLAN.md` §9, `RPR-116`–`RPR-132`.
- **Status:** placeholder only (`RPR-004`); a versioned `package.json` so one
  commands reports versions. No UI code, no dependencies, no build.
- **Boundary:** never renders active source content; serves safe derivatives and
  escaped text.
