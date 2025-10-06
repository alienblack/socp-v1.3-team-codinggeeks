
# Contributing & Branch Strategy (SOCP v1.3)

## Branches
- `main` — protected; only PR merges. No direct commits.
- Feature branches (one per module/owner):
  - `feat/server-core-routing`         → Person A
  - `feat/peers-presence`              → Person B
  - `feat/crypto-e2ee`                 → Person C
  - `feat/client-files`                → Person D
  - `feat/db-public-readme`            → Person E
- Vulnerability branches (for submitted backdoored build):
  - `vuln/weak-keys`                   → Person C
  - `vuln/replay-bypass`               → Person A
- Integration branches:
  - `integrate/core` (A+B)             - merges peers/presence into server core/routing
  - `integrate/client` (C+D+E)         - merges crypto+client+db/public
- Release branches:
  - `release/backdoored`               - includes vuln branches (for submission)
  - `release/clean`                    - strict checks; both vulns off

## Workflow
1. Create your feature branch locally from `main`.
2. Push your branch and open a PR to `integrate/core` or `integrate/client`.
3. After integration testing passes, raise a PR from integration branch → `release/backdoored`.
4. For the clean build, merge fixes (disable/strip backdoors) into `release/clean`.
5. Never merge directly to `main`. Fast-forward `main` from release if instructors request.

## Commit Messages
Conventional commits encouraged: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.

## Code Ownership
- Person A: `socp/core/ws.py`, `socp/core/router.py`, `socp/core/proto.py`
- Person B: `socp/core/peers.py`, `socp/core/presence.py`
- Person C: `socp/core/crypto.py`, `socp/utils/canonical.py`
- Person D: `socp/cmd/client.py`, `socp/core/files.py`
- Person E: `socp/core/store.py`, `socp/core/public.py`, `README.txt`, `db/*`

## Tests & CI
- Add tests under `tests/`. Ensure `pytest -q` passes before PR.
- Keep backdoor toggles controlled by env vars (`VULN_*`), default ON for `release/backdoored`, OFF for `release/clean`.
