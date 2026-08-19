# web — LAN web interface

Owner: the browser UI built later as a React/TypeScript static SPA.

- **Source of truth:** `docs/MASTER_PLAN.md` §9, `RPR-116`–`RPR-132`.
- **Status:** scaffold manifest plus the RPR-116 design-system foundation and
  the RPR-117 application shell. No React/TypeScript code, no build, no
  dependencies.
- **Boundary:** never renders active source content; serves safe derivatives and
  escaped text.

## Design system (RPR-116)

The deterministic, dependency-free design-system foundation lives in
`web/design-system/`:

- `tokens.json` — versioned design-token source of truth (colors per theme,
  typography, spacing, radii, status colors, and required WCAG AA contrast
  pairs). Schema: `scripts/schemas/design-tokens.schema.json`.
- `tokens.css` — CSS custom properties derived from `tokens.json`, including a
  `prefers-color-scheme: dark` override block. No ad-hoc values are allowed.
- `catalog.html` — static, accessible component catalog (buttons, inputs,
  status chips, tables, cards, skeletons, dialog, toast). It uses only
  `--rpr-*` tokens, a visible `:focus-visible` ring, reduced-motion handling,
  labelled inputs, and correct ARIA, with no third-party assets or branding.

`scripts/design_system_check.py` (run through `scripts/frontend-test.py` via
`make frontend-test`) verifies the token schema, the CSS derivation, WCAG AA
contrast ratios in both themes, catalog token/URL/structure rules, and
keyboard/focus/accessibility basics. Screenshots remain a manual release check
recorded in the RPR-116 acceptance criteria.

## Application shell (RPR-117)

`web/app-shell/` is the deterministic, dependency-free application shell:

- `index.html` — responsive sidebar/top status, all planned tabs, case/source
  context, connection-state indicator, a persistent unauthenticated-LAN
  critical warning, route-level loading/error boundaries, and a strict
  single-origin CSP.
- `app-shell.css` — layout using only `--rpr-*` design tokens, responsive
  breakpoint, `:focus-visible`, and `prefers-reduced-motion` handling.
- `app-shell.js` — dependency-free behavior: EventSource with bounded SSE
  reconnect (backoff with attempt cap), route loading/error helpers that write
  dynamic text with `textContent` only, and no `innerHTML`, `eval`, or inline
  handlers.

`scripts/app_shell_check.py` (also run through `make frontend-test`) verifies
these rules deterministically; `tests/test_app_shell.py` covers the acceptance
and failure paths.
