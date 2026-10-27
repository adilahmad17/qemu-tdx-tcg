#!/bin/sh
# tdx-expect-reset.sh OUT LOG MESSAGE QEMU ARGS...: run QEMU with -no-reboot
# and the reset log (-d cpu_reset -D LOG), and expect the guest to end in a
# triple fault: QEMU exits with status 0, LOG says "Triple fault", the guest
# output OUT contains MESSAGE and no FAIL.
out=$1 log=$2 msg=$3
shift 3
rm -f "$log"
"$@" -no-reboot -d cpu_reset -D "$log"
status=$?
cat "$out"
if [ "$status" -ne 0 ]; then
    echo "expected exit status 0 (a reset with -no-reboot), got $status" >&2
    exit 1
fi
grep -q "Triple fault" "$log" || { echo "no triple fault in $log" >&2; exit 1; }
grep -q "$msg" "$out" || { echo "the output does not contain: $msg" >&2; exit 1; }
if grep -q FAIL "$out"; then
    echo "the guest went on after the #VE" >&2
    exit 1
fi
exit 0
