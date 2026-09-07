#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <licenses.csv> <license-files-dir> <output>" >&2
    exit 1
fi

in="$1"
license_dir="$2"
out="$3"

csv_tmp="$(mktemp)"
trap 'rm -f "$csv_tmp"' EXIT
awk -F, '$1 !~ /^fencer\/cli(\/|$)/ {print}' "$in" >"$csv_tmp"
csv="$csv_tmp"

if [ ! -s "$csv" ]; then
    echo "error: license report is empty: $in" >&2
    exit 1
fi

disallowed='GPL-2.0|GPL-2.0-only|GPL-2.0-or-later|GPL-3.0|GPL-3.0-only|GPL-3.0-or-later|AGPL-3.0|AGPL-3.0-only|AGPL-3.0-or-later|LGPL-2.1|LGPL-2.1-only|LGPL-2.1-or-later|LGPL-3.0|LGPL-3.0-only|LGPL-3.0-or-later|SSPL-1.0|BUSL-1.1|CC-BY-NC|CC-BY-NC-SA'

bad="$(awk -F, '{print $3}' "$csv" | grep -E "^($disallowed)$" || true)"
if [ -n "$bad" ]; then
    echo "error: disallowed license(s) for binary redistribution:" >&2
    echo "$bad" >&2
    exit 1
fi

unknown="$(awk -F, '{print $3}' "$csv" | grep -E '^(Unknown|unsupported)$' || true)"
if [ -n "$unknown" ]; then
    echo "error: unknown license(s) in report; classify them before shipping:" >&2
    awk -F, '$3 == "Unknown" || $3 == "unsupported" {print}' "$csv" >&2
    exit 1
fi

{
    printf '%s\n' "Third-Party Notices"
    printf '%s\n' "==================="
    printf '\n'
    printf '%s\n' "The Fencer CLI binary includes the following third-party Go modules."
    printf '%s\n' "Copyright and license text for each module follows. This file is generated"
    printf '%s\n' "at release time from the module graph of ./cmd/fencer."
    printf '\n'
    printf '%s\n' "The Fencer CLI itself is proprietary software of Fencer, Inc. See LICENSE"
    printf '%s\n' "in this archive and the Fencer Subscription Services Agreement."
    printf '\n'
    printf '%s\n' "------------------------------------------------------------------------"
    printf '\n'
    awk -F, '{
		mod=$1
		url=$2
		lic=$3
		printf "Package: %s\nLicense: %s\nSource:  %s\n\n", mod, lic, url
	}' "$csv"
    printf '%s\n' "------------------------------------------------------------------------"
    printf '%s\n' "License texts"
    printf '%s\n' "------------------------------------------------------------------------"
    printf '\n'
} >"$out"

if [ -d "$license_dir" ]; then
    find "$license_dir" -type f | sort | while IFS= read -r f; do
        rel="${f#"$license_dir"/}"
        {
            printf '%s\n' "===== $rel ====="
            printf '\n'
            cat "$f"
            printf '\n\n'
        } >>"$out"
    done
fi

echo "wrote $out ($(wc -l <"$out") lines)"
