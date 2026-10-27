#!/usr/bin/env bash
# Headless Sha2Test runner under Amiberry-in-Docker.
#
# Same shape as sha1-thread-test/amiberry/run-headless.sh next door, and
# it MOUNTS THAT TEST'S SYS DRIVE rather than keeping a second copy: the
# boot drive is 15 MB of AmiSSL distribution and its Startup-Sequence
# already runs whatever binary is on DH1, so there is nothing in it that
# is specific to either test. That also means this script and its UAE
# config sit at the example root rather than in an `amiberry/` drawer,
# which .gitignore excludes precisely because of that 15 MB.
#
# Bind mounts:
#   * /conf/threadtest.uae.template ← per-test UAE config (the image's
#                                     entrypoint always reads this path)
#   * /amiga-sys                    ← boot drive (DH0), shared
#   * /app                          ← built binary directory (DH1)
#
# Caller must point KICK31 at a kickstart 3.1 ROM (defaults to the
# FS-UAE setup the user already has):
#   KICK31=$HOME/Documents/FS-UAE/Kickstarts/kick31.rom ./run-m68k.sh
#
# Exit codes:
#   0 — completion sentinel "=== TEST RUN COMPLETE ===" detected in log
#   1 — build artefact missing, image missing, or sentinel never appeared
#
# What the log should say: a PASS line per vector and
# "RESULT: ALL VECTORS MATCH". The run-level sentinel only means the
# program got to the end — grep for the RESULT line to know it was right.
#
# KNOWN BLOCKER (2026-10-27): on this rig it stops at the first digest,
# inside am-crypto's shared AmiSSL bring-up, and the trace points at
# OPENSSL_init_ssl never returning. RAND_seed next to it does the same,
# while the plain C around them runs fine — so every AmiSSL library call
# hangs rather than anything being wrong with a digest. It is not
# specific to SHA-2: Sha1.digest, which predates this example, stops at
# the same place. Until that is fixed this script will time out, which
# is why it is here — it is the thing that will say when it is.

set -u
set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$HERE/builds/bin/amigaos"
TEMPLATE="$HERE/sha2test.uae.template"
SYS_DIR="$HERE/../sha1-thread-test/amiberry/sys"
KICK31="${KICK31:-$HOME/Documents/FS-UAE/Kickstarts/kick31.rom}"
# Longer than sha1-thread-test's 120s: PBKDF2 at 4096 iterations runs
# three times here, and being slow is the entire point of the function.
RUN_TIMEOUT="${RUN_TIMEOUT:-300}"

if [[ ! -f "$APP_DIR/app" ]]; then
    echo "Amiga build not found at $APP_DIR/app — run 'make build-amigaos' first" >&2
    exit 1
fi

if [[ ! -f "$KICK31" ]]; then
    echo "Kickstart ROM not found at $KICK31" >&2
    echo "Point KICK31 at your kick31.rom:" >&2
    echo "  KICK31=/path/to/kick31.rom $0" >&2
    exit 1
fi

if [[ ! -d "$SYS_DIR" ]]; then
    echo "SYS staging not found at $SYS_DIR (it lives in the sha1-thread-test example)" >&2
    exit 1
fi

if [[ -z "$(docker images -q amiberry:latest)" ]]; then
    echo "amiberry:latest not found — build it via am-lang-compiler-code/amiberry-docker/build.sh" >&2
    exit 1
fi

echo "Launching Amiberry headlessly (timeout ${RUN_TIMEOUT}s)..."
docker run --rm \
    -e RUN_TIMEOUT="$RUN_TIMEOUT" \
    -v "$KICK31:/rom/kick31.rom:ro" \
    -v "$APP_DIR:/app" \
    -v "$TEMPLATE:/conf/threadtest.uae.template:ro" \
    -v "$SYS_DIR:/amiga-sys" \
    amiberry:latest
status=$?

# The amiberry image writes output.log to DH1, which maps to $APP_DIR on
# the host — inside builds/, so it is ignored along with the binary and
# there is nothing to tidy up afterwards.
if [[ -f "$APP_DIR/output.log" ]]; then
    echo "----- output.log -----"
    cat "$APP_DIR/output.log"
    echo "----- end -----"
fi

exit "$status"
