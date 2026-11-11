#!/usr/bin/env bash
set -e
test $(whoami) = "_vibecollector" || ( echo "must be run via sudo -u _vibecollector $0" ; exit 1 );
cd /var/lib/vibecollector
/usr/libexec/vibecollector/manage.bin "$@"

