#!/usr/bin/env bash

# Starts the given command while monitoring that the parent is alive.
# Is the parent dies, it kills the command, with all its child processes.
# If the child dies, it will kill the parent that started it all.
#
# This is useful in cases where you have a process spawning children
# which is killed by SIGKILL. Since this can't be trapped, the children
# continue running.

function killem () {
        kill `ps --ppid "$1" -n -o pid --no-headers` "$1"
}

if [[ "$1" =~ ^[0-9]+$ ]]; then
    level="$1"
    watchpid="$2"
    shift 2
else
    level=0
    watchpid=$$
fi

if [ "$level" -gt 1 ]; then
    "$@" &
    child="$!"
    while ps -p "$watchpid" &>/dev/null && ps -p "$child" &>/dev/null ; do
        sleep 1;
    done
    if ps -p "$child" &>/dev/null; then
        killem "$child"
    fi
    if ps -p "$watchpid" &>/dev/null; then
        killem "$watchpid"
    fi
    exit
fi

setsid "$0" "$((level + 1))" "${watchpid}" "$@" &

if [ "$level" -eq 0 ]; then
   while sleep 5; do :; done
fi
