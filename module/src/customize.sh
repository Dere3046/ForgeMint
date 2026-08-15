#
# This file is part of ForgeStore
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program;
# if not, see <https://www.gnu.org/licenses/>.
#
# Copyright (C) 2026 TheGeniusClub
#

##FUNCTIONS##
#OTHER#
abort_verify() {
  ui_print "***********************************************"
  ui_print "! $@"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "***********************************************"
}
##END##

##VARIABLE##
#INSTALL PROCESS#
SKIPUNZIP=1
#PUBLIC#
FSCONFIG="/data/adb/forge_store"
#CHECK ENVIRONMENT#
MIN_RELEASE=10
RELEASE=$(grep_get_prop ro.build.version.release)
if [ "$KSU" ]; then
  KernelSU=true
elif [ "$APATCH" ]; then
  APatch=true
elif [ "$MAGISK_VER" ]; then
  Magisk=true
fi
#PRINT INFORMATION#
MODULE_VER=$(grep_prop version "$TMPDIR/module.prop")
#EXTRACT MODULE FILES#
FILES="
lib/$ARCH/*
daemon
mistylake.$ARCH
module.prop
sepolicy.rule
service.apk
service.sh
"
#POST PROCESS#
N755S="
$MODPATH/lib/libinject.so
$MODPATH/daemon
"
##END##

##PRE PROCESS##
#CHECK INTEGRITY#
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >/dev/null
[ -f "$TMPDIR/verify.sh" ] || abort_verify "Unable to extract verify.sh"
source "$TMPDIR/verify.sh"
#CHECK ENVIRONMENT#
[ "$BOOTMODE" ] || {
  ui_print "***********************************************"
  ui_print "! Install from recovery is not supported"
  abort "***********************************************"
}
[ "$RELEASE" -lt $MIN_RELEASE ] && {
  ui_print "***********************************************"
  ui_print "! Unsupported android version: $RELEASE"
  ui_print "! Minimal supported android version is $MIN_RELEASE"
  abort "***********************************************"
}
case "$ARCH" in
  x64|x86|arm|arm64)
    ui_print "- Device arch: $ARCH"
    ;;
  *)
    abort "! Unsupported arch: $ARCH"
    ;;
esac
if [ "$KernelSU" ]; then
  ui_print "- KernelSU version code: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  ui_print "- KernelSU version: $KSU_VER"
elif [ "$APatch" ]; then
  ui_print "- APatch version code: $APATCH_VER_CODE"
  ui_print "- APatch version: $APATCH_VER"
elif [ "$Magisk" ]; then
  ui_print "- Magisk version code: $MAGISK_VER_CODE"
  ui_print "- Magisk version: $MAGISK_VER"
fi
#PRINT INFORMATION#
ui_print "- Install module ForgeStore $MODULE_VER"
sleep 1s
##END##

##EXTRACT MODULE FILES##
ui_print "- Extracting general files"
for FILE in $FILES; do
  extract "$ZIPFILE" "$FILE" "$MODPATH"
done

ui_print "- Processing $ARCH libraries"
mv -f "$MODPATH/lib/$ARCH"/* "$MODPATH/lib/"
rmdir "$MODPATH/lib/$ARCH"
mv -f "$MODPATH/mistylake.$ARCH" "$MODPATH/mistylake"
##END##

##POST PROCESS##
ui_print "- Setting permissions"
for N755 in $N755S; do
  set_perm "$N755" 0 0 0755
done

ui_print "- Setting up config directory"
[ -d "$FSCONFIG" ] || {
  ui_print "- Creating configuration directory"
  mkdir -p "$FSCONFIG"
}
[ -f "$FSCONFIG/target.txt" ] || {
  ui_print "- Adding default target scope"
  extract "$ZIPFILE" 'target.txt' "$FSCONFIG"
}
[ -f "$FSCONFIG/hbk" ] || {
  dd if=/dev/random of="$FSCONFIG/hbk" bs=32 count=1 2>/dev/null
  ui_print "- Generated HBK seed"
}
##END##

ui_print "- Install Done"