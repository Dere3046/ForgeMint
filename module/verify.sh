#!/sbin/sh
# Copyright (C) 2026  TheGeniusClub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.

verify_module() {
    local zipfile="$1"
    local total=0
    local verified=0
    local failed=0

    ui_print "- Verifying module integrity"

    local files=$(unzip -l "$zipfile" | awk 'NR>3&&!/-----/{print $4}' | tail -n +2 | grep -v '/$')
    for f in $files; do
        [ -z "$f" ] && continue
        case "$f" in *.sha256) continue ;; esac

        local sidecar="$f.sha256"
        local expected=$(unzip -p "$zipfile" "$sidecar" 2>/dev/null)
        [ -z "$expected" ] && continue

        total=$((total + 1))
        local actual=$(unzip -p "$zipfile" "$f" 2>/dev/null | sha256sum | cut -d' ' -f1)

        if [ "$expected" = "$actual" ]; then
            verified=$((verified + 1))
        else
            ui_print "  MISMATCH: $f"
            failed=$((failed + 1))
        fi
    done

    if [ "$failed" -gt 0 ]; then
        abort "! Verification failed: $failed/$total file(s) mismatched"
    fi
    ui_print "- Verified $verified files"
}
