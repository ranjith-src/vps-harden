#!/bin/sh
# The container is not --privileged, so the sysctls of the host's kernel stay read-only.
# Open up only what belongs to the container: its cgroup and its network namespace.
# The remounts are per-mount (bind): rootless Docker refuses to touch the cgroup filesystem itself.
mount -o remount,rw,bind /sys/fs/cgroup
mount --bind /proc/sys/net /proc/sys/net
mount -o remount,rw,bind /proc/sys/net
exec /sbin/init
