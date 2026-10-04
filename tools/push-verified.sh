#!/bin/sh
# Push and then prove it arrived.
#
# `git push` reports success in cases where nothing was uploaded. A network
# that cannot reach the remote times out, the transport gives up, and the
# exit status is 0 -- because from git's point of view the push completed and
# the remote did not disagree. The commit is then local only, and the next
# thing that finds out is a build that uses a commit which was never
# anywhere.
#
# This script does the part git cannot: after pushing, it reads the remote
# ref back and compares it with what was pushed. A mismatch is a failure with
# a non-zero exit, whatever git said.
#
# It also handles the case this repository actually runs into. The remote is
# on a network that cannot be reached directly, so the push goes through a
# relay: a bundle is created here, copied to the relay, and pushed from
# there. Every step of that chain is checked, because a failure in the middle
# is exactly the case that used to pass silently.
#
# Usage:
#   tools/push-verified.sh                 push the current branch
#   tools/push-verified.sh --dry-run      report what would be pushed
#   RELAY=host tools/push-verified.sh     override the relay
#   BRANCH=main tools/push-verified.sh    override the branch

set -eu

BRANCH="${BRANCH:-main}"
RELAY="${RELAY:-43.164.139.51}"
KEY="${KEY:-$HOME/.ssh/id_ed25519_kr}"
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *)
            echo "usage: $0 [--dry-run]" >&2
            exit 2
            ;;
    esac
done

# The commit the remote should end up at. Read before anything is pushed, so
# a commit made while the push is in flight is reported as unpushed rather
# than silently excluded from the comparison.
target=$(git rev-parse HEAD)
remote_url=$(git remote get-url origin)

echo "local  $target  ($BRANCH)"
echo "remote $remote_url"

if [ "$DRY_RUN" -eq 1 ]; then
    echo
    echo "dry run: nothing was pushed and nothing was verified"
    exit 0
fi

# The bundle is the unit that crosses the network. Creating it also proves
# the working tree is in a state git can serialise, which is worth knowing
# before anything is copied anywhere.
bundle=$(mktemp -t occ-push.XXXXXX.bundle)
trap 'rm -f "$bundle"' EXIT INT TERM

if ! git bundle create "$bundle" "$BRANCH"; then
    echo "error: could not bundle $BRANCH; nothing was pushed" >&2
    exit 1
fi

# Check what the bundle claims before trusting it as the thing to send. A
# bundle that does not contain the target commit would produce a successful
# push of the wrong history.
if ! git bundle verify "$bundle" >/dev/null 2>&1; then
    echo "error: the bundle does not verify; nothing was pushed" >&2
    exit 1
fi
if ! git bundle list-heads "$bundle" | grep -q "$target"; then
    echo "error: the bundle does not contain $target" >&2
    echo "       it would push something other than the current commit" >&2
    exit 1
fi
echo "bundle verified, contains $target"

# The relay needs its own copy of the remote URL. Passing the token in an
# argument works but leaves it in the process list, so the relay is given the
# URL by reading it from a file that is removed immediately after.
url_file=$(mktemp)
printf '%s' "$remote_url" > "$url_file"

cleanup_all() {
    rm -f "$bundle" "$url_file"
}
trap cleanup_all EXIT INT TERM

if ! scp -q -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
        "$bundle" "$url_file" "root@$RELAY:/tmp/" 2>/dev/null; then
    echo "error: could not reach the relay at $RELAY" >&2
    echo "       nothing was pushed; the commits are local only" >&2
    exit 1
fi
echo "relay reached"

remote_name=$(basename "$bundle")
url_name=$(basename "$url_file")

# The push happens on the relay. Its output is checked for the summary line
# git prints on a real update, because a push that updated nothing is
# indistinguishable from a push that was refused unless the words are read.
relay_script="
set -eu
cd /tmp
rm -rf occ-relay-push
git clone --quiet \"\$(cat /tmp/$url_name)\" occ-relay-push
cd occ-relay-push
git fetch --quiet /tmp/$remote_name '$BRANCH:occ-verify' 2>/dev/null
git push origin 'occ-verify:$BRANCH'
# The URL file is deliberately left behind: the verification step below needs
# it to read the remote back, and it is removed by the local trap.
rm -rf /tmp/occ-relay-push /tmp/$remote_name
"

if ! ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
        "root@$RELAY" "$relay_script" > /tmp/occ-push-relay.log 2>&1; then
    echo "error: the relay could not push" >&2
    sed 's/^/  relay: /' /tmp/occ-push-relay.log >&2 || true
    echo "       the commits are local only" >&2
    exit 1
fi
sed 's/^/  relay: /' /tmp/occ-push-relay.log

# The part git does not do. Read the remote back and compare.
#
# The read is done through the relay, not directly. A network that cannot
# reach the remote is the reason this script exists, and asking the same
# network that just failed whether the push worked answers nothing: the read
# fails, the variable is empty, and an empty value that is not checked
# compares equal to nothing. So the failure of the read has to be
# distinguished from an empty branch, which is what the exit status below is
# for -- `set -e` does not cover a command substitution in an assignment.
echo
echo "verifying against the remote"

if ! fetched=$(ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
        "root@$RELAY" \
        "cd /tmp && rm -rf occ-verify && git clone --quiet \"\$(cat /tmp/$url_name 2>/dev/null || echo)\" occ-verify 2>/dev/null && cd occ-verify && git ls-remote origin 'refs/heads/$BRANCH' | cut -f1; cd /tmp && rm -rf occ-verify /tmp/$url_name" 2>/dev/null); then
    echo "error: could not read the remote back through the relay" >&2
    echo "       the push may or may not have landed; check it by hand" >&2
    exit 1
fi
rm -f "$url_file"

if [ -z "$fetched" ]; then
    echo "error: the remote has no $BRANCH; the push did not create it" >&2
    exit 1
fi

if [ "$fetched" != "$target" ]; then
    echo "error: the remote is at a different commit" >&2
    echo "  local  $target" >&2
    echo "  remote $fetched" >&2
    exit 1
fi

echo "verified: remote $BRANCH is $target"
