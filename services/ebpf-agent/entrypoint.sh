#!/bin/sh
# libbpf attaches tracepoints through tracefs; privileged pods do not get it mounted.
set -e
if ! [ -e /sys/kernel/tracing/events ] && ! [ -e /sys/kernel/debug/tracing/events ]; then
    mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug || true
fi
exec python3 -m ids_agent "$@"
