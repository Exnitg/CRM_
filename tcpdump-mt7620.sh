#!/bin/sh
# Скрипт-обертка для запуска tcpdump
SCRIPT_DIR=$(dirname "$0")
exec "$SCRIPT_DIR/tcpdump-mt7620" "$@"
