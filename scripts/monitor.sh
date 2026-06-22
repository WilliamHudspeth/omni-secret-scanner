#!/usr/bin/env bash
# ============================================================================
# omni-secret-scanner — Cron monitoring + webhook alerting
#
# Usage:
#   ./scripts/monitor.sh /path/to/repo [--webhook https://hooks.slack.com/...]
#
# Set up as a cron job:
#   0 */6 * * * /path/to/scripts/monitor.sh /path/to/repo --quiet
#
# Or with webhook alerts:
#   ./scripts/monitor.sh /path/to/repo --webhook https://hooks.slack.com/xxx
# ============================================================================

set -euo pipefail

REPO_DIR="${1:-.}"
shift || true

QUIET=""
WEBHOOK_URL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet) QUIET="--quiet" ;;
        --webhook) WEBHOOK_URL="$2"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

cd "$REPO_DIR"

# Pull latest if it's a git repo
if [ -d .git ]; then
    git pull --ff-only origin "$(git rev-parse --abbrev-ref HEAD)" 2>/dev/null || true
fi

# Run the scan
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCAN_OUTPUT=$(mktemp)
trap "rm -f $SCAN_OUTPUT" EXIT

omni-scan --fast --format json --output "$SCAN_OUTPUT" --confidence-score $QUIET 2>/dev/null || true

# Parse results
ISSUES=$(python3 -c "
import json
data = json.load(open('$SCAN_OUTPUT'))
print(data['summary'].get('total_issues', 0))
" 2>/dev/null || echo "0")

SAFETY=$(python3 -c "
import json
data = json.load(open('$SCAN_OUTPUT'))
print(data['summary'].get('safety_score', 100))
" 2>/dev/null || echo "100")

VALIDATED_LIVE=$(python3 -c "
import json
data = json.load(open('$SCAN_OUTPUT'))
print(data['summary'].get('valid_live', 0))
" 2>/dev/null || echo "0")

if [ "$QUIET" != "--quiet" ]; then
    echo "[$TIMESTAMP] Repo: $REPO_DIR | Issues: $ISSUES | Safety: $SAFETY/100 | Live: $VALIDATED_LIVE"
fi

# Alert if critical
if [ "$VALIDATED_LIVE" -gt 0 ]; then
    MESSAGE=":rotating_light: *CRITICAL: Validated live secrets found!*
    Repo: \`$REPO_DIR\`
    Live secrets: $VALIDATED_LIVE
    Total issues: $ISSUES
    Safety score: $SAFETY/100
    Time: $TIMESTAMP"

    echo "$MESSAGE"

    if [ -n "$WEBHOOK_URL" ]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"$MESSAGE\"}" \
            > /dev/null 2>&1 || true
    fi
elif [ "$ISSUES" -gt 0 ] && [ "$QUIET" != "--quiet" ]; then
    echo "  Issues found ($ISSUES) but none validated live. Run: omni-scan to review."
fi
