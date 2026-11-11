# preremove.sh  (deb)
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload >/dev/null || true
fi
exit 0