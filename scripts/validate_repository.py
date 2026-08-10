#!/usr/bin/env python3
"""Dependency-free repository policy checks shared by contributors and CI."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
MAX_REPOSITORY_FILE_BYTES = 5 * 1024 * 1024
EXPECTED_BACKLOG_IDS = {f"RPR-{number:03d}" for number in range(1, 178)}
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"

FORBIDDEN_ROOT_DIRECTORIES = {
    ".reperio",
    "artifacts",
    "checkpoints",
    "derivatives",
    "exports",
    "models",
    "recovered",
    "scratch",
    "secrets",
    "state",
    "var",
    "wordlists",
}
FORBIDDEN_MEDIA_SUFFIXES = {
    ".aff",
    ".aff4",
    ".dd",
    ".e01",
    ".img",
    ".iso",
    ".raw",
    ".vdi",
    ".vhd",
    ".vhdx",
    ".vmdk",
}
FORBIDDEN_SECRET_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"}
FORBIDDEN_DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
ALLOWED_ENVIRONMENT_FILES = {
    ".env.example",
    ".env.template",
}


def git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def repository_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = ROOT / os.fsdecode(raw_path)
        if path.exists() or path.is_symlink():
            paths.append(path)
    return sorted(paths)


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def text_content(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def check_secret_signatures(files: list[Path]) -> list[str]:
    private_key_marker = "-----BEGIN " + r"(?:[A-Z0-9]+ )?PRIVATE KEY-----"
    patterns = {
        "private key": re.compile(private_key_marker),
        "GitHub token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        "AWS access key": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
        "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "Google API key": re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
        "Anthropic API key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    }
    failures = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            continue
        content = text_content(path)
        if content is None:
            continue
        for label, pattern in patterns.items():
            match = pattern.search(content)
            if match:
                line_number = content.count("\n", 0, match.start()) + 1
                failures.append(f"{relative(path)}:{line_number}: possible {label}")
    return failures


def check_repository_paths(files: list[Path]) -> list[str]:
    failures = []
    private_names = {
        ".netrc",
        ".npmrc",
        ".pypirc",
        "auth.json",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
    for path in files:
        name = path.name
        rel = relative(path)
        parts = Path(rel).parts
        suffix = path.suffix.lower()

        if path.is_symlink():
            failures.append(f"{rel}: symbolic links are not allowed in the repository")
        if parts and parts[0].lower() in FORBIDDEN_ROOT_DIRECTORIES:
            failures.append(f"{rel}: Reperio runtime/recovery data must not be committed")
        if name == ".env" or (
            name.startswith(".env.")
            and name not in ALLOWED_ENVIRONMENT_FILES
            and not name.endswith(".example")
            and not name.endswith(".template")
        ):
            failures.append(f"{rel}: environment/secret file must not be committed")
        if name in private_names or name.startswith(("id_rsa_", "id_dsa_", "id_ecdsa_", "id_ed25519_")):
            failures.append(f"{rel}: credential file must not be committed")
        if suffix in FORBIDDEN_SECRET_SUFFIXES:
            failures.append(f"{rel}: private key or keystore file must not be committed")
        if suffix in FORBIDDEN_MEDIA_SUFFIXES:
            failures.append(f"{rel}: disk images/source media must be generated outside Git")
        if suffix in FORBIDDEN_DATABASE_SUFFIXES or name.endswith((".sqlite-shm", ".sqlite-wal")):
            failures.append(f"{rel}: runtime database must not be committed")
        if path.is_file() and path.stat().st_size > MAX_REPOSITORY_FILE_BYTES:
            failures.append(f"{rel}: file exceeds the 5 MiB repository limit")
        if any(ord(character) < 32 for character in rel):
            failures.append(f"{rel!r}: control characters are not allowed in file names")
    return failures


def check_text_hygiene(files: list[Path]) -> list[str]:
    failures = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            continue
        content = text_content(path)
        if content is None:
            continue
        if content and not content.endswith("\n"):
            failures.append(f"{relative(path)}: missing final newline")
        if content.endswith("\n\n"):
            failures.append(f"{relative(path)}: extra blank line at end of file")
        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.endswith((" ", "\t")):
                failures.append(f"{relative(path)}:{line_number}: trailing whitespace")
    return failures


def check_markdown_links(files: list[Path]) -> list[str]:
    failures = []
    markdown_link = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
    for path in files:
        if path.suffix.lower() != ".md" or path.is_symlink():
            continue
        content = text_content(path)
        if content is None:
            continue
        for match in markdown_link.finditer(content):
            raw_target = match.group(1).strip().split(maxsplit=1)[0].strip("<>")
            target = unquote(raw_target.split("#", 1)[0])
            if not target or target.startswith(("#", "/", "mailto:")) or "://" in target:
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                failures.append(f"{relative(path)}: link escapes the repository: {raw_target}")
                continue
            if not resolved.exists():
                line_number = content.count("\n", 0, match.start()) + 1
                failures.append(f"{relative(path)}:{line_number}: broken local link: {raw_target}")
    return failures


def check_backlog(files: list[Path]) -> list[str]:
    backlog = ROOT / "docs" / "BACKLOG.md"
    if not backlog.exists():
        return ["docs/BACKLOG.md: master backlog is missing"]
    content = backlog.read_text(encoding="utf-8")
    definitions = re.findall(r"^### (RPR-\d{3})\b", content, flags=re.MULTILINE)
    counts = Counter(definitions)
    failures = []

    missing = sorted(EXPECTED_BACKLOG_IDS - set(definitions))
    unexpected = sorted(set(definitions) - EXPECTED_BACKLOG_IDS)
    duplicates = sorted(identifier for identifier, count in counts.items() if count != 1)
    if missing:
        failures.append("docs/BACKLOG.md: missing task definitions: " + ", ".join(missing))
    if unexpected:
        failures.append("docs/BACKLOG.md: unexpected task definitions: " + ", ".join(unexpected))
    if duplicates:
        failures.append("docs/BACKLOG.md: duplicate task definitions: " + ", ".join(duplicates))

    known = set(definitions)
    for path in files:
        if path.suffix.lower() != ".md" or path.is_symlink():
            continue
        text = text_content(path)
        if text is None:
            continue
        for identifier in set(re.findall(r"\bRPR-\d{3}\b", text)):
            if identifier not in known:
                failures.append(f"{relative(path)}: references undefined task {identifier}")
    return failures


def check_json(files: list[Path]) -> list[str]:
    failures = []
    for path in files:
        if path.suffix.lower() != ".json" or path.is_symlink():
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            failures.append(f"{relative(path)}: invalid JSON: {error}")
    return failures


def workflow_job_blocks(content: str) -> list[tuple[str, str]]:
    lines = content.splitlines()
    try:
        jobs_index = next(index for index, line in enumerate(lines) if line == "jobs:")
    except StopIteration:
        return []
    blocks = []
    current_name = None
    current_lines: list[str] = []
    for line in lines[jobs_index + 1 :]:
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            if current_name is not None:
                blocks.append((current_name, "\n".join(current_lines)))
            current_name = match.group(1)
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)
    if current_name is not None:
        blocks.append((current_name, "\n".join(current_lines)))
    return blocks


def check_workflows() -> list[str]:
    failures = []
    workflows = sorted(WORKFLOW_DIRECTORY.glob("*.y*ml")) if WORKFLOW_DIRECTORY.exists() else []
    if not workflows:
        return [".github/workflows: at least one validation workflow is required"]

    for path in workflows:
        content = path.read_text(encoding="utf-8")
        rel = relative(path)
        if re.search(r"^\s*(pull_request_target|workflow_run):", content, flags=re.MULTILINE):
            failures.append(f"{rel}: privileged untrusted-code trigger is prohibited")
        if not re.search(r"^permissions:\s*\n(?:  [^\n]+\n)*?  contents: read\s*$", content, flags=re.MULTILINE):
            failures.append(f"{rel}: top-level permissions must include contents: read")
        if re.search(r"^\s+[A-Za-z-]+:\s*write\s*$", content, flags=re.MULTILINE):
            failures.append(f"{rel}: write permissions require an explicit policy exception")

        uses = re.findall(r"^\s*-\s+uses:\s*([^\s#]+)", content, flags=re.MULTILINE)
        for action in uses:
            if action.startswith("./"):
                continue
            if not re.search(r"@[0-9a-f]{40}$", action):
                failures.append(f"{rel}: action must be pinned to a full commit SHA: {action}")

        lines = content.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
            if not match:
                continue
            indent = len(match.group(1))
            run_value = match.group(2)
            run_lines = [run_value]
            if run_value in {"|", "|-", ">", ">-"}:
                run_lines = []
                for following in lines[index + 1 :]:
                    following_indent = len(following) - len(following.lstrip())
                    if following.strip() and following_indent <= indent:
                        break
                    run_lines.append(following)
            if "${{" in "\n".join(run_lines):
                failures.append(f"{rel}:{index + 1}: pass GitHub context through env, not run interpolation")

        blocks = workflow_job_blocks(content)
        if not blocks:
            failures.append(f"{rel}: workflow has no jobs")
        for name, block in blocks:
            if "runs-on:" not in block:
                failures.append(f"{rel}: job {name} must declare runs-on")
            if "timeout-minutes:" not in block:
                failures.append(f"{rel}: job {name} must declare timeout-minutes")
    return failures


def check_shell_scripts(files: list[Path]) -> list[str]:
    failures = []
    for path in files:
        if path.suffix != ".sh" or path.is_symlink():
            continue
        result = subprocess.run(
            ["bash", "-n", str(path)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode:
            failures.append(f"{relative(path)}: shell syntax error: {result.stdout.strip()}")
    return failures


def check_git_whitespace() -> list[str]:
    failures = []
    for arguments in (("diff", "--check"), ("diff", "--cached", "--check")):
        result = git(*arguments)
        if result.returncode:
            failures.append("git " + " ".join(arguments) + ":\n" + result.stdout.strip())
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-only", action="store_true")
    args = parser.parse_args()

    files = repository_files()
    checks = [("high-confidence secret signatures", check_secret_signatures(files))]
    if not args.secrets_only:
        checks.extend(
            [
                ("repository paths and sizes", check_repository_paths(files)),
                ("text hygiene", check_text_hygiene(files)),
                ("Markdown links", check_markdown_links(files)),
                ("backlog integrity", check_backlog(files)),
                ("JSON syntax", check_json(files)),
                ("GitHub workflow policy", check_workflows()),
                ("shell syntax", check_shell_scripts(files)),
                ("Git whitespace", check_git_whitespace()),
            ]
        )

    failed = False
    for label, failures in checks:
        if failures:
            failed = True
            print(f"FAIL: {label}")
            for failure in failures:
                print(f"  - {failure}")
        else:
            print(f"PASS: {label}")

    if failed:
        print("Repository validation failed.")
        return 1
    print("Repository validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
