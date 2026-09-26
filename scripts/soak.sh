#!/usr/bin/env bash
# Feed soak launcher: runs `osint-board soak run` unattended until its deadline and resumes it after a crash.
#
# Usage:
#   scripts/soak.sh [--infra] [--out DIR] [--hours H] [--only ID]... [--sink db|null]
#                   [--report-every S] [--sample-every S]
#
#   --infra     start an isolated Postgres + Redis for the soak (compose project "osint-board-soak", ports
#               127.0.0.1:55432 and 127.0.0.1:56379, volumes of its own), run `alembic upgrade head` against it
#               and point the soak at it (OSINT_DATABASE_URL / OSINT_REDIS_URL are exported). It keeps running
#               afterwards so the data can be inspected: `docker compose -p osint-board-soak down` (-v drops it).
#   --out DIR   run directory (default data/soak/<UTC timestamp>). An unfinished run in DIR is resumed with its
#               original deadline; stop a running soak and start this script again with the same --out to resume.
#   the other options go to `osint-board soak run` (`cd backend && uv run osint-board soak run --help`);
#   without --sink the soak writes to the database (--sink db), so use --infra or have `make infra` running.
#
# The soak's stdout/stderr are appended to DIR/soak.log (JSON log lines unless OSINT_LOG_JSON is set otherwise);
# DIR/report.md is rewritten every 5 min.
# Exit status: 0 the run completed; 3 it was interrupted (SIGINT/SIGTERM to this script or to the soak, which
# also stops this loop); 1 a launcher error or the soak could not be kept running. Any other exit of the soak
# is a crash: it is resumed after 30 s (SOAK_RESTART_DELAY). Once the deadline has passed without a clean end,
# `osint-board soak report DIR --final` writes the final report, so DIR/report.md always ends up FINAL.
#
# Detached (survives closing the terminal):
#   setsid nohup scripts/soak.sh --infra > /dev/null 2>&1 &
#   tail -f data/soak/*/soak.log                    # follow it
#   pkill -TERM -f 'scripts/soak.sh'                # stop it cleanly (run.end reason=interrupted)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
PROJECT="osint-board-soak"
PG_PORT="${SOAK_POSTGRES_PORT:-55432}"
REDIS_PORT_SOAK="${SOAK_REDIS_PORT:-56379}"
RESTART_DELAY="${SOAK_RESTART_DELAY:-30}"
MAX_START_FAILURES=5 # consecutive exits before run.json exists (a broken install, not a flaky feed)

usage() {
    sed -n '2,/^set -euo pipefail/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"
}

say() { printf 'soak: %s\n' "$*"; }
die() {
    printf 'soak: %s\n' "$*" >&2
    exit 1
}
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

infra=0
out=""
args=()
while (($#)); do
    case "$1" in
    --infra)
        infra=1
        shift
        ;;
    --out)
        (($# >= 2)) || die "--out needs a directory"
        out="$2"
        shift 2
        ;;
    --out=*)
        out="${1#--out=}"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        args+=("$1")
        shift
        ;;
    esac
done

command -v uv >/dev/null 2>&1 || die "uv is required (https://docs.astral.sh/uv/)"
out="${out:-$ROOT/data/soak/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
LOG="$out/soak.log"

# A variable from the environment, else from the repo's .env (as docker compose reads it), else a default.
env_value() {
    local name="$1" default="$2" value=""
    if [[ -n "${!name:-}" ]]; then
        printf '%s' "${!name}"
        return
    fi
    if [[ -f "$ROOT/.env" ]]; then
        value="$(grep -E "^[[:space:]]*${name}=" "$ROOT/.env" | tail -n 1 | cut -d= -f2- || true)"
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
    fi
    printf '%s' "${value:-$default}"
}

start_infra() {
    command -v docker >/dev/null 2>&1 || die "--infra needs docker (with the compose plugin)"
    local user password db
    user="$(env_value POSTGRES_USER osint)"
    password="$(env_value POSTGRES_PASSWORD osint)"
    db="$(env_value POSTGRES_DB osint)"
    say "starting an isolated postgres + redis (compose project $PROJECT, ports $PG_PORT / $REDIS_PORT_SOAK)"
    (cd "$ROOT" && POSTGRES_PORT="$PG_PORT" REDIS_PORT="$REDIS_PORT_SOAK" \
        docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.dev.yml up -d --wait db redis) || die "could not start the soak infrastructure"
    export OSINT_DATABASE_URL="postgresql+asyncpg://${user}:${password}@127.0.0.1:${PG_PORT}/${db}"
    export OSINT_REDIS_URL="redis://127.0.0.1:${REDIS_PORT_SOAK}/0"
    say "migrating the soak database"
    (cd "$BACKEND" && uv run alembic upgrade head) >>"$LOG" 2>&1 || die "alembic upgrade head failed (see $LOG)"
}

# True when run.json exists and its deadline has passed.
deadline_passed() {
    [[ -f "$out/run.json" ]] || return 1
    (cd "$BACKEND" && uv run --quiet python -c \
        'import json, sys, time; sys.exit(0 if time.time() >= json.load(open(sys.argv[1]))["deadline_t"] else 1)' \
        "$out/run.json") 2>/dev/null
}

stop=0
child=""
on_signal() {
    stop=1
    if [[ -n "$child" ]]; then
        kill -TERM "$child" 2>/dev/null || true
    fi
}
trap on_signal INT TERM

# Run `soak run` in the background (so a signal to this script can be forwarded) and return its exit status.
run_soak() {
    local rc=0 again=0
    (cd "$BACKEND" && exec uv run osint-board soak run --out "$out" ${args[@]+"${args[@]}"}) >>"$LOG" 2>&1 &
    child=$!
    while :; do
        rc=0
        wait "$child" || rc=$?
        kill -0 "$child" 2>/dev/null || break # still running: wait was cut short by a signal we forwarded
    done
    if ((rc > 128)); then # the signal may have interrupted wait just as the soak exited: ask for its own status
        wait "$child" 2>/dev/null || again=$?
        ((again == 127)) || rc=$again
    fi
    child=""
    return "$rc"
}

if ((infra)); then
    start_infra
fi
export OSINT_LOG_JSON="${OSINT_LOG_JSON:-true}" # soak.log gets one JSON object per log line (no ANSI colours)

say "output directory: $out"
say "log: $LOG"
code=0
start_failures=0
while :; do
    printf '[%s] soak.sh: starting `osint-board soak run --out %s %s`\n' "$(stamp)" "$out" "${args[*]-}" >>"$LOG"
    code=0
    run_soak || code=$?
    printf '[%s] soak.sh: soak run exited with status %s\n' "$(stamp)" "$code" >>"$LOG"
    case "$code" in
    0)
        say "run completed"
        break
        ;;
    3)
        say "run interrupted"
        break
        ;;
    2)
        say "the soak refused to start (usage error or a finished run in $out; see $LOG)" >&2
        break
        ;;
    esac
    ((stop)) && break
    if [[ ! -f "$out/run.json" ]]; then
        start_failures=$((start_failures + 1))
        if ((start_failures >= MAX_START_FAILURES)); then
            say "giving up: the soak failed to start $start_failures times in a row (see $LOG)" >&2
            break
        fi
    else
        start_failures=0
        if deadline_passed; then
            say "the deadline passed while the soak was down"
            break
        fi
    fi
    say "the soak exited with status $code; resuming in ${RESTART_DELAY}s (see $LOG)"
    sleep "$RESTART_DELAY" &
    wait $! || true
    ((stop)) && break
done

# Guarantee a report: FINAL once the deadline has passed (or the run ended), IN PROGRESS for a resumable run.
if ((code != 0)) && [[ -f "$out/run.json" ]]; then
    final=()
    if deadline_passed; then
        final=(--final)
    fi
    (cd "$BACKEND" && uv run osint-board soak report "$out" ${final[@]+"${final[@]}"}) >>"$LOG" 2>&1 ||
        say "writing the report failed (see $LOG)" >&2
fi
[[ -f "$out/report.md" ]] && say "report: $out/report.md"
say "output directory: $out"
((infra)) && say "soak infrastructure still running: docker compose -p $PROJECT down   # add -v to drop its data"

if ((code == 0)); then
    exit 0
elif ((code == 3 || stop)); then
    exit 3
fi
exit 1
