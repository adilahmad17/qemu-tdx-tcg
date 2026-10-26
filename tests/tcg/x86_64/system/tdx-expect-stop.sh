#!/bin/sh
# tdx-expect-stop.sh MESSAGE QEMU ARGS...: run QEMU and expect the strict TD
# emulation to stop it (exit status 1) with MESSAGE on stderr.
msg=$1
shift
err=$("$@" 2>&1 >/dev/null)
status=$?
echo "$err"
if [ "$status" -ne 1 ]; then
    echo "expected exit status 1, got $status" >&2
    exit 1
fi
case $err in
    *"$msg"*) exit 0 ;;
    *) echo "the stop message does not contain: $msg" >&2; exit 1 ;;
esac
