# GitHub repository setup

Repository files provide local checks and GitHub workflow definitions, but they cannot protect `main` or enable server-side security features by themselves. This checklist matches the current single-owner workflow: one implementation agent, one task, one checkout, and direct task commits to `main`. Section 1.1 documents the optional PR mode if the owner later changes that decision.

## 1. Protect `main` for the current sequential-owner mode

In **Settings → Rules → Rulesets**, create a branch ruleset targeting the default branch `main`:

- Set enforcement to **Active**.
- Restrict deletions and block force pushes.
- Require a linear history.
- Do not require pull requests or pre-push status checks while direct-to-`main` owner mode is active. A new commit cannot earn its own GitHub-hosted checks until GitHub receives it, so local `make validate`, task tests, `make secret-scan`, and diff review are mandatory before push.
- Keep direct pushes limited to the owner. GitHub Actions runs `repository-policy` and `secret-scan` after every `main` push. A failure keeps the same task active until a corrective commit passes; never rewrite the failed commit out of history.
- Do not create broad bypass entries. If an emergency bypass is ever used, record why and immediately restore enforcement.

This mode gives up pre-merge enforcement in exchange for the requested no-branch/no-worktree workflow. Git remains the audit trail, force-push/deletion protection preserves history, and local plus post-push gates provide validation.

### 1.1 Optional pull-request mode

If the owner later requests PR-based review, edit the ruleset to require pull requests, conversation resolution, up-to-date branches, and these status checks:

- `repository-policy`
- `secret-scan`
- `dependency-review`

Use zero required approvals only while there is one trusted owner; add approvals and CODEOWNERS review when a second trusted reviewer exists. GitHub normally requires a check to have run before it can be selected, so open a disposable documentation PR and let the workflow finish first. Switching to PR mode does not authorize parallel implementation agents.

## 2. Restrict GitHub Actions

In **Settings → Actions → General**:

- Allow only the GitHub-owned Actions used by the workflow, or use the repository's selected-action allowlist. Gitleaks and Actionlint run as checksum-verified release binaries rather than third-party Actions.
- Require actions to be pinned to a full-length commit SHA.
- Set the default `GITHUB_TOKEN` permission to **read repository contents and packages**.
- Do not allow workflows to create or approve pull requests.
- Require approval before workflows from first-time or outside contributors run.

The workflow also declares `contents: read`, disables checkout credential persistence, uses timeouts and concurrency cancellation, and prohibits `pull_request_target`/`workflow_run` through local policy. Future release workflows that need package, attestation, or identity-token writes must be separate, narrowly permissioned, environment-protected, and independently reviewed.

## 3. Enable repository security features

In **Settings → Security / Code security and analysis**:

- Enable the dependency graph.
- Enable Dependabot alerts and Dependabot security updates.
- Enable secret scanning and push protection wherever the repository/account plan exposes them.
- Keep private vulnerability reporting enabled so `SECURITY.md` and the issue-template link work.
- Enable code scanning when application code enters the repository and the selected language/tool configuration is defined.

`.github/dependabot.yml` currently updates pinned GitHub Actions weekly. Add package ecosystems only when their real manifest and lockfile exist; do not create empty or speculative dependency configurations.

## 4. Configure merge and repository behavior

In **Settings → General**:

- Keep `main` as the default branch.
- If optional PR mode is used, enable automatic deletion of merged head branches and prefer squash or rebase merges that retain linear history.
- Keep issues enabled for backlog task packets and security reports routed privately.
- Add repository topics and a description only after the README's claims match an implemented milestone.

Do not publish a release or advertise the installer until the M5 release tasks are complete, artifacts are signed, images are digest-pinned, and the documented acceptance run passes.

## 5. Validate the protection

For current sequential-owner mode:

1. Run `make validate`, task tests, and `make secret-scan` before a scoped documentation commit.
2. Push normally and confirm `repository-policy` and `secret-scan` pass for the exact `main` commit.
3. Inspect the active ruleset and confirm deletion and force-push protections target `main`; do not perform a destructive test against `main`.
4. Confirm a normal non-force follow-up push remains possible for the owner.
5. Confirm Dependabot can open an Action update that preserves a full-SHA pin and updates its version comment.

For optional PR mode, additionally use a disposable branch/PR to confirm all three required checks appear and a PR cannot merge while a check is failing or pending. Use only inert synthetic secret-scanner fixtures and remove them before merge; never test a broken gate by pushing deliberately invalid content to `main`.

Record the ruleset export or screenshots in private operational documentation if company change-control evidence is required. Do not store account secrets, personal drive content, or recovered reports in this repository.

## 6. Future CI/CD boundary

The current workflow is CI only; it does not deploy or publish. When delivery work begins:

- Build from protected tags or merged `main`, never an unreviewed pull-request context.
- Use GitHub environments for release approval and least-privilege credentials.
- Prefer short-lived OpenID Connect identity over long-lived cloud secrets.
- Generate an SBOM, provenance/attestation, signatures, checksums, and immutable OCI digests.
- Separate build, security verification, and release promotion so a build cannot silently publish itself.
- Keep production/device credentials unavailable to pull-request workflows and untrusted forks.
