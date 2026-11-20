#!/usr/bin/env bash
# Print every citation of a protocol machine next to the upstream line it
# points at, to check the citations after a change, or to find those that
# moved when the machine is brought to a new upstream release.
#
# Usage: scripts/protocol-cites.sh core|bchn UPSTREAM_CHECKOUT
#
#   core  the machine of Bitcoin Core, src/Haskoin/Network/Protocol/BitcoinCore
#   bchn  the machine of Bitcoin Cash Node,
#         src/Haskoin/Network/Protocol/BitcoinCashNode
#
# UPSTREAM_CHECKOUT is a Git checkout of the upstream repository. The script
# warns when it is not at the commit that the machine names in `upstream`.
#
# Each citation prints as two lines: where it is in the Haskell source, the
# upstream file and line, and the reason; then the upstream line itself.
# A citation whose reason is on the next line of the Haskell source prints
# without its reason.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 core|bchn UPSTREAM_CHECKOUT" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
case "$1" in
  core) module=BitcoinCore ;;
  bchn) module=BitcoinCashNode ;;
  *)
    echo "unknown machine: $1 (core or bchn)" >&2
    exit 2
    ;;
esac
upstream=$2
src="$root/src/Haskoin/Network/Protocol"

# The commit that the machine translates, from its `upstream`.
want=$(
  grep -rho 'commit = "[0-9a-f]*"' "$src/$module.hs" "$src/$module" |
    cut -d'"' -f2
)
have=$(git -C "$upstream" rev-parse HEAD 2>/dev/null || echo unknown)
if [ "$want" != "$have" ]; then
  echo "warning: $upstream is at $have, the machine cites $want" >&2
fi

# The helpers of the machine, each bound to one upstream file, such as
#   netProcessing = cite "src/net_processing.cpp"
declare -A files
while read -r name file; do
  files[$name]=$file
done < <(
  grep -h '^[a-zA-Z]* = cite "' "$src/$module/Constants.hs" |
    sed 's/^\([a-zA-Z]*\) = cite "\([^"]*\)".*/\1 \2/'
)

# Every call of a helper, or of cite itself, with its line number and its
# reason when the reason is on the same line.
helpers=$(printf '%s\|' "${!files[@]}")
grep -rnoE "(${helpers//\\|/|}cite \"[^\"]+\") [0-9]+( *\"[^\"]*\")?" \
  "$src/$module.hs" "$src/$module" |
  while IFS= read -r hit; do
    where=${hit%%:[a-zA-Z]*}
    call=${hit#"$where":}
    name=${call%% *}
    rest=${call#* }
    if [ "$name" = cite ]; then
      file=$(echo "$rest" | cut -d'"' -f2)
      rest=${rest#*\" }
    else
      file=${files[$name]}
    fi
    line=${rest%% *}
    reason=$(echo "$rest" | sed -n 's/^[0-9]* *"\(.*\)"$/\1/p')
    printf '%s  %s:%s  %s\n' "${where#"$root"/}" "$file" "$line" "$reason"
    printf '    | %s\n' "$(sed -n "${line}p" "$upstream/$file" | sed 's/^ *//')"
  done
