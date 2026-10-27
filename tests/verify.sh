#!/bin/sh
# Optional bounded proofs, fuzzing, and interpreter checks.
set -u
cd "$(dirname "$0")/.." || exit 1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-5}"
export CARGO_PROFILE_RELEASE_INCREMENTAL=true
export UV_CACHE_DIR=target/uv-cache
mkdir -p target/verification

wait_for_load() {
    if [ ! -r /proc/loadavg ]; then
        uptime
        echo 'Skipping the Linux load check: /proc/loadavg is unavailable.'
        return
    fi
    while ! awk -v limit="$(($(nproc) * 2))" '{ exit !($1 <= limit) }' /proc/loadavg; do
        uptime
        sleep 15
    done
}

kani_checks() {
    wait_for_load
    cargo kani --lib -Z unstable-options \
        --harness-timeout 300s --jobs "$CARGO_BUILD_JOBS" \
        --output-format terse --export-json target/verification/kani.json
}

fuzz_checks() {
    uv run --no-project tests/fuzz_runner_test.py || return 1
    wait_for_load
    uv run --no-project tests/fuzz.py "$@"
}

miri_checks() {
    wait_for_load
    cargo +nightly miri test --lib instruction_words -- --test-threads 5 || return 1
    cargo +nightly miri test --lib leb_overflow -- --test-threads 5 || return 1
    cargo +nightly miri test --lib record_readers_bound -- --test-threads 5 || return 1
    cargo +nightly miri test --bin velk closed_pipe_signal -- --test-threads 5 > target/verification/miri-signal.log 2>&1
    result=$?
    cat target/verification/miri-signal.log
    if [ "$result" -ne 0 ]; then
        if grep -q '^error: unsupported operation:.*`signal`' target/verification/miri-signal.log; then
            echo 'Miri could not interpret the signal call; see the log.'
        else
            return "$result"
        fi
    fi
    echo 'AArch64 macOS code execution and inline assembly require native hardware; see docs/TESTING.md.'
}

mode=${1:-all}
if [ "$#" -gt 0 ]; then shift; fi
status=0
case "$mode" in
    kani) kani_checks || status=1 ;;
    fuzz) fuzz_checks "$@" || status=1 ;;
    miri) miri_checks || status=1 ;;
    all)
        kani_checks || status=1
        fuzz_checks "$@" || status=1
        miri_checks || status=1
        ;;
    *) echo 'Usage: sh tests/verify.sh [all|kani|fuzz|miri] [fuzz options]' >&2; exit 2 ;;
esac
exit "$status"
