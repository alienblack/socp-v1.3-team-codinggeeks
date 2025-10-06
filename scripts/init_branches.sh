
#!/usr/bin/env bash
set -euo pipefail
# Initialize branches for the team workflow
git checkout -b feat/server-core-routing
git push -u origin feat/server-core-routing || true

git checkout main
git checkout -b feat/peers-presence
git push -u origin feat/peers-presence || true

git checkout main
git checkout -b feat/crypto-e2ee
git push -u origin feat/crypto-e2ee || true

git checkout main
git checkout -b feat/client-files
git push -u origin feat/client-files || true

git checkout main
git checkout -b feat/db-public-readme
git push -u origin feat/db-public-readme || true

git checkout main
git checkout -b integrate/core
git push -u origin integrate/core || true

git checkout main
git checkout -b integrate/client
git push -u origin integrate/client || true

git checkout main
git checkout -b vuln/weak-keys
git push -u origin vuln/weak-keys || true

git checkout main
git checkout -b vuln/replay-bypass
git push -u origin vuln/replay-bypass || true

git checkout main
git checkout -b release/backdoored
git push -u origin release/backdoored || true

git checkout main
git checkout -b release/clean
git push -u origin release/clean || true

echo "Branches created and pushed (if remote was set)."
