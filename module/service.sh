#!/system/bin/sh
MODDIR=${0%/*}

cd $MODDIR

while true; do
    ./daemon "$MODDIR" || exit 1
    sleep 3
done &
