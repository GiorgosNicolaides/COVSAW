# Security Notes

CryptoAnalyzer is a **defensive** static-analysis tool: it reads Python source code
and reports cryptographic weaknesses. This document describes what it does that is
security-relevant, how it would be hardened for a real deployment, and its known
limitations.

## What this project does that is security-relevant

- **Analyzes untrusted source code.** Targets may be arbitrary files, directories,
  or public GitHub repositories. Input is treated as data: files are parsed with the
  standard-library `ast.parse` and **never executed or imported**, which avoids
  arbitrary code execution from a malicious target.
- **Shallow-clones remote repositories.** When the target is a GitHub URL the tool
  runs `git clone --depth 1` into a temporary directory, scans it, and deletes it.
  Git is invoked with an argument list (`subprocess.run([...])`) — not a shell
  string — so the URL is not interpolated into a shell command.
- **Maps findings to CWE identifiers**, the standard taxonomy used by SAST tooling,
  so results are interoperable with other security workflows.

## What I would harden for a real deployment

- **Sandbox the clone/scan step.** Run untrusted clones in a container or jailed
  user with no network egress, a disk quota, CPU/time limits, and a read-only mount,
  to contain a hostile repository (e.g. zip-bomb-style huge files or symlink tricks).
- **Validate and constrain the target.** Allowlist permitted Git hosts, enforce a
  maximum repository/file size and file count, and reject symlinks that escape the
  scan root before reading them.
- **Resource limits on parsing.** Extremely large or deeply nested files can exhaust
  memory/stack in `ast.parse`; cap file size and recursion before parsing.
- **Pin and audit dependencies.** Pin exact versions (lockfile), enable dependency
  vulnerability scanning, and verify integrity hashes in CI.
- **Harden report output.** The HTML reporter embeds findings (including file paths
  and code-derived messages) into a page; ensure all interpolated values are
  HTML-escaped to prevent stored-XSS if a report is viewed in a shared context.
- **Secure temp-directory handling.** Create clone directories with restrictive
  permissions and guarantee cleanup even on crash (e.g. context manager / `finally`).

## Known limitations and assumptions

- **Static analysis only.** The tool reasons about syntactic patterns in the AST. It
  does not perform data-flow or taint analysis, so it can produce **false positives**
  (flagging safe usage) and **false negatives** (missing weaknesses expressed in a
  form no rule matches, e.g. via dynamic dispatch, `getattr`, or aliasing).
- **Python only.** Only `.py` files are analyzed.
- **Heuristic rules.** Detections encode common mistakes; they are not a proof of
  (in)security. A clean scan does not mean the code is cryptographically sound.
- **Known gap:** the weak-hash rule does not currently flag `hmac.new(...)` calls
  whose digest defaults to or specifies MD5; this is tracked as a detection
  limitation rather than a guarantee.
- **Trust in the input path.** The tool assumes the operator chose to scan the given
  target; it does not itself authenticate or authorize remote URLs.

## Reporting an issue

This is a student portfolio project and is not operated as a service. If you find a
security issue in the code, please open an issue or contact the author rather than
filing it publicly with exploit details.
