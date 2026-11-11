# postinstall.sh  (deb: $1 = configure|abort-upgrade|...)
set -e

if [ "$1" = "configure" ] ; then
  /usr/libexec/vibecollector/create-system-user.sh
  conf=/etc/vibecollector.toml
  [ -f $conf ] || (
    echo Generate initial config: $conf ; (
      ( vibecollector-genconf > $conf && chmod 640 $conf && chown root:_vibecollector $conf ) || (
        echo "Failed to generate ${conf}" ; exit 1
      )
    )
  )

  if [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload
    systemctl preset vibecollector.service
    systemctl restart vibecollector.service
  fi
fi

exit 0