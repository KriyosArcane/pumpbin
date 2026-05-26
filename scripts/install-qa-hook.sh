#!/usr/bin/env bash
#
# Install a git pre-push hook that runs scripts/qa-execute.sh whenever
# the user pushes a tag matching v*.*.*. Other pushes are unaffected.
#
# Idempotent — re-running just overwrites the hook.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_DIR="$REPO_ROOT/.git/hooks"
HOOK="$HOOK_DIR/pre-push"

if [[ ! -d "$REPO_ROOT/.git" ]]; then
    echo "install-qa-hook: $REPO_ROOT is not a git repo" >&2
    exit 1
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK" <<'HOOK'
#!/usr/bin/env bash
#
# pre-push: gate `git push <remote> vX.Y.Z` on the execute-QA harness.
#
# Stdin format (per `man githooks`):
#   <local ref> <local sha> <remote ref> <remote sha>
# one line per ref being pushed.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HARNESS="$REPO_ROOT/scripts/qa-execute.sh"

needs_qa=0
while read -r local_ref _local_sha remote_ref _remote_sha; do
    if [[ "$local_ref" == refs/tags/v*.*.* ]] || \
       [[ "$remote_ref" == refs/tags/v*.*.* ]]; then
        needs_qa=1
    fi
done

if [[ "$needs_qa" -eq 0 ]]; then
    exit 0
fi

if [[ ! -x "$HARNESS" ]]; then
    echo "pre-push QA gate: $HARNESS missing or not executable" >&2
    exit 1
fi

echo "pre-push: release tag detected, running execute-QA harness..." >&2
if "$HARNESS"; then
    echo "pre-push: QA passed, allowing push." >&2
    exit 0
else
    echo "pre-push: QA FAILED. Push aborted." >&2
    echo "          Re-run with: $HARNESS" >&2
    echo "          Or skip QA (only if you know why): git push --no-verify ..." >&2
    exit 1
fi
HOOK

chmod +x "$HOOK"
echo "installed: $HOOK"
echo "test with: bash $HOOK <<< 'refs/tags/v9.9.9 deadbeef refs/tags/v9.9.9 0000'"
