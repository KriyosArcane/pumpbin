#!/usr/bin/env bash
#
# PumpBin QA-execute harness.
#
# What it does:
#   1. Build pumpbin-cli (debug) if not already built.
#   2. For each platform (linux, windows):
#       a. Generate a fresh run-id and sentinel path.
#       b. Patch the run-id into a copy of the sentinel shellcode.
#       c. Invoke pumpbin-cli generate to stamp the loader.
#       d. Execute the stamped artifact (locally for Linux, over
#          ssh pumpbin-w10 for Windows) with a hard timeout.
#       e. Poll for the sentinel file containing "PB-QA-OK".
#       f. Clean up sentinel + temp files.
#   3. Exit 0 iff every selected platform passed.
#
# Flags:
#   --linux-only           Skip Windows.
#   --windows-only         Skip Linux.
#   --ssh-host HOST        Override SSH host (default: pumpbin-w10).
#   --keep-artifacts       Don't delete the stamped binaries (debugging).
#
# Env overrides:
#   PUMPBIN_QA_SKIP_WINDOWS=1  Same as --linux-only.
#   PUMPBIN_QA_SSH_HOST        Same as --ssh-host.
#   PUMPBIN_QA_TIMEOUT=30      Per-execute timeout in seconds.
#
# Exit codes:
#   0   all selected platforms passed
#   1   linux failed
#   2   windows failed
#   3   both failed
#   10  setup error (missing fixture, build failure, ssh unreachable)

set -uo pipefail

# -------- paths ----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures/qa"
CLI="$REPO_ROOT/target/debug/pumpbin-cli"

# -------- options --------------------------------------------------
DO_LINUX=1
DO_WINDOWS=1
SSH_HOST="${PUMPBIN_QA_SSH_HOST:-pumpbin-w10}"
TIMEOUT="${PUMPBIN_QA_TIMEOUT:-30}"
KEEP_ARTIFACTS=0

[[ "${PUMPBIN_QA_SKIP_WINDOWS:-0}" == "1" ]] && DO_WINDOWS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --linux-only)     DO_WINDOWS=0; shift ;;
        --windows-only)   DO_LINUX=0;   shift ;;
        --ssh-host)       SSH_HOST="$2"; shift 2 ;;
        --keep-artifacts) KEEP_ARTIFACTS=1; shift ;;
        -h|--help)
            sed -n '3,30p' "$0"
            exit 0
            ;;
        *)
            echo "qa-execute: unknown flag: $1" >&2
            exit 10
            ;;
    esac
done

# -------- helpers --------------------------------------------------
log()  { printf '[qa] %s\n' "$*" >&2; }
fail() { printf '[qa] FAIL: %s\n' "$*" >&2; }
ok()   { printf '[qa] OK:   %s\n' "$*" >&2; }

new_run_id() {
    # 16 hex chars, lowercase. Deterministic length so we know how
    # much room we need inside the 64/128-byte placeholder.
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8
    else
        head -c 8 /dev/urandom | xxd -p
    fi
}

# patch_path BLOB_IN PATH BLOB_OUT
# Find the run of >=32 'X' bytes in BLOB_IN and overwrite the leading
# bytes with PATH + NUL, write to BLOB_OUT.
patch_path() {
    local in="$1" path="$2" out="$3"
    python3 - "$in" "$path" "$out" <<'PY'
import sys
src, path, dst = sys.argv[1], sys.argv[2].encode(), sys.argv[3]
data = bytearray(open(src, 'rb').read())
i = data.find(b'X' * 32)
if i < 0:
    sys.exit('placeholder not found in ' + src)
if len(path) >= 64:  # leave room for NUL even in the 64-byte linux blob
    sys.exit('path too long: ' + path.decode())
for j, b in enumerate(path):
    data[i + j] = b
data[i + len(path)] = 0
open(dst, 'wb').write(data)
PY
}

# -------- prereqs --------------------------------------------------
[[ -d "$FIXTURES" ]] || { fail "fixtures dir missing: $FIXTURES"; exit 10; }
for f in linux_sentinel.bin linux_loader.b1n windows_sentinel.bin windows_loader.b1n; do
    [[ -f "$FIXTURES/$f" ]] || { fail "missing fixture: $f"; exit 10; }
done

if [[ ! -x "$CLI" ]]; then
    log "building pumpbin-cli (debug)..."
    (cd "$REPO_ROOT" && cargo build --bin pumpbin-cli) || {
        fail "cargo build failed"; exit 10;
    }
fi

WORKDIR="$(mktemp -d -t pumpbin-qa.XXXXXX)"
trap '[[ $KEEP_ARTIFACTS -eq 0 ]] && rm -rf "$WORKDIR"' EXIT

# -------- linux ----------------------------------------------------
linux_status=skip
if [[ $DO_LINUX -eq 1 ]]; then
    RUN_ID="$(new_run_id)"
    SENTINEL="/tmp/pumpbin_qa_${RUN_ID}"
    BLOB="$WORKDIR/linux_sc.bin"
    IMPLANT="$WORKDIR/linux_implant"

    log "[linux] run_id=$RUN_ID sentinel=$SENTINEL"
    rm -f "$SENTINEL"
    patch_path "$FIXTURES/linux_sentinel.bin" "$SENTINEL" "$BLOB" \
        || { fail "[linux] patch_path"; exit 10; }
    "$CLI" --no-log generate \
            -p "$FIXTURES/linux_loader.b1n" \
            -s "$BLOB" \
            --platform linux -t exe \
            -o "$IMPLANT" >/dev/null 2>&1 \
        || { fail "[linux] generate"; linux_status=fail; }

    if [[ "$linux_status" != "fail" ]]; then
        chmod +x "$IMPLANT"
        timeout "$TIMEOUT" "$IMPLANT"
        if [[ -f "$SENTINEL" ]] && [[ "$(cat "$SENTINEL")" == "PB-QA-OK" ]]; then
            ok "[linux] sentinel written"
            linux_status=pass
        else
            fail "[linux] sentinel missing or wrong content"
            linux_status=fail
        fi
        rm -f "$SENTINEL"
    fi
fi

# -------- windows --------------------------------------------------
windows_status=skip
if [[ $DO_WINDOWS -eq 1 ]]; then
    if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_HOST" \
            'C:\Windows\System32\cmd.exe /c "echo PING"' >/dev/null 2>&1; then
        fail "[win]   ssh $SSH_HOST unreachable"
        windows_status=fail
    else
        RUN_ID="$(new_run_id)"
        REMOTE_SENTINEL="C:\\Users\\Public\\pumpbin_qa_${RUN_ID}.txt"
        REMOTE_EXE="C:\\Users\\Public\\pumpbin_qa_${RUN_ID}.exe"
        # Forward slash form for scp (OpenSSH on Windows accepts it).
        REMOTE_EXE_SCP="C:/Users/Public/pumpbin_qa_${RUN_ID}.exe"
        BLOB="$WORKDIR/win_sc.bin"
        IMPLANT="$WORKDIR/win_implant.exe"

        log "[win]   run_id=$RUN_ID sentinel=$REMOTE_SENTINEL"
        patch_path "$FIXTURES/windows_sentinel.bin" "$REMOTE_SENTINEL" "$BLOB" \
            || { fail "[win] patch_path"; exit 10; }
        "$CLI" --no-log generate \
                -p "$FIXTURES/windows_loader.b1n" \
                -s "$BLOB" \
                --platform windows -t exe \
                -o "$IMPLANT" >/dev/null 2>&1 \
            || { fail "[win] generate"; windows_status=fail; }

        if [[ "$windows_status" != "fail" ]]; then
            scp -o BatchMode=yes -q "$IMPLANT" "$SSH_HOST:$REMOTE_EXE_SCP" \
                || { fail "[win] scp"; windows_status=fail; }
        fi

        if [[ "$windows_status" != "fail" ]]; then
            # Use cmd.exe explicit path (the ssh-mcp wrapper requires
            # the first token to be an absolute program path; raw ssh
            # is less picky but we keep the cmd /c form for parity).
            REMOTE_CMD="C:\\Windows\\System32\\cmd.exe /c \"del /q \"$REMOTE_SENTINEL\" 2>nul & \"$REMOTE_EXE\" & echo EXIT=%ERRORLEVEL% & if exist \"$REMOTE_SENTINEL\" (type \"$REMOTE_SENTINEL\") else (echo NO_SENTINEL) & del /q \"$REMOTE_EXE\" 2>nul & del /q \"$REMOTE_SENTINEL\" 2>nul\""
            out="$(timeout "$TIMEOUT" ssh -o BatchMode=yes "$SSH_HOST" "$REMOTE_CMD" 2>&1)"
            if echo "$out" | grep -q '^PB-QA-OK'; then
                ok "[win]   sentinel written"
                windows_status=pass
            else
                fail "[win]   sentinel missing"
                printf '%s\n' "$out" | sed 's/^/[win]   /' >&2
                windows_status=fail
            fi
        fi
    fi
fi

# -------- summary --------------------------------------------------
printf '\n=== QA summary ===\n'
printf 'linux:   %s\n' "$linux_status"
printf 'windows: %s\n' "$windows_status"

rc=0
[[ "$linux_status"   == "fail" ]] && rc=$((rc | 1))
[[ "$windows_status" == "fail" ]] && rc=$((rc | 2))
exit "$rc"
