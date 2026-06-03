#!/bin/bash
# RaPLT test suite runner
set -e

cd "$(dirname "$0")"

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

tests=(
    test_sleb128
    test_batch
    test_hash
    test_elf
    test_core
    test_got_patch
    test_signal_safety
    test_hook
    test_region
)

echo "=========================================="
echo "  RaPLT Test Suite"
echo "=========================================="
echo ""

for t in "${tests[@]}"; do
    if [ ! -x "./$t" ]; then
        echo "  BUILD  $t"
        continue
    fi
    echo "  TEST   $t"
    TOTAL=$((TOTAL + 1))
    set +e
    ./$t
    rc=$?
    set -e
    if [ $rc -eq 77 ]; then
        SKIPPED=$((SKIPPED + 1))
        echo "         [SKIP]"
    elif [ $rc -eq 0 ]; then
        PASSED=$((PASSED + 1))
        echo "         [PASS]"
    else
        FAILED=$((FAILED + 1))
        echo "         [FAIL] (exit $rc)"
    fi
    echo ""
done

echo "=========================================="
echo "  Results: $PASSED passed  $FAILED failed  $SKIPPED skipped  ($TOTAL total)"
echo "=========================================="

[ $FAILED -eq 0 ] && exit 0 || exit 1
