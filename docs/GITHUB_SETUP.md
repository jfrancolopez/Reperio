# GitHub repository setup

Repository files provide local checks and GitHub workflow definitions, but they cannot protect `main` or enable server-side security features by themselves. Apply this checklist once the hardening branch is reviewed and pushed.

## 1. Create an active `main` ruleset

In **Settings → Rules → Rulesets**, create a branch ruleset targeting the default branch `main`:

- Set enforcement to **Active**.
- Restrict deletions and block force pushes.
- Require changes to be made through a pull request.
- In the current single-owner phase, use zero required approvals so the owner is not permanently blocked from merging their own pull request. Add at least one approval and required CODEOWNERS review as soon as a second trusted reviewer exists.
- Require conversation resolution.
- Require a linear history if squash or rebase merges are the chosen merge strategies.
- Require these status checks:
  - `repository-policy`
  - `secret-scan`
  - `dependency-review`
- Require branches to be up to date before merging.
- Do not create broad bypass entries. If an emergency bypass is ever used, record why and immediately restore enforcement.

GitHub normally requires a check to have run successfully in the repository before it can be selected as required. Open the first pull request, let the workflow run, then finish the required-check selection.

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
- Enable automatic deletion of merged head branches.
- Prefer squash merge for one-task pull requests, or rebase merge if individual task commits are intentionally curated.
- Disable merge commits if linear history is required by the ruleset.
- Keep issues enabled for backlog task packets and security reports routed privately.
- Add repository topics and a description only after the README's claims match an implemented milestone.

Do not publish a release or advertise the installer until the M5 release tasks are complete, artifacts are signed, images are digest-pinned, and the documented acceptance run passes.

## 5. Validate the protection

Use a disposable pull request to prove enforcement:

1. Make a harmless documentation change and confirm all three required checks appear.
2. Add a temporary intentionally broken local link and confirm `repository-policy` fails; remove it afterward.
3. Use a synthetic fake pattern supported by the scanner's test guidance—never a live credential—and confirm `secret-scan` fails; remove it afterward.
4. Confirm a direct push to `main` is rejected once the ruleset is active.
5. Confirm a pull request cannot merge with a failing or pending required check.
6. Confirm Dependabot can open an Action update that preserves a full-SHA pin and updates its version comment.

Record the ruleset export or screenshots in private operational documentation if company change-control evidence is required. Do not store account secrets, personal drive content, or recovered reports in this repository.

## 6. Future CI/CD boundary

The current workflow is CI only; it does not deploy or publish. When delivery work begins:

- Build from protected tags or merged `main`, never an unreviewed pull-request context.
- Use GitHub environments for release approval and least-privilege credentials.
- Prefer short-lived OpenID Connect identity over long-lived cloud secrets.
- Generate an SBOM, provenance/attestation, signatures, checksums, and immutable OCI digests.
- Separate build, security verification, and release promotion so a build cannot silently publish itself.
- Keep production/device credentials unavailable to pull-request workflows and untrusted forks.
