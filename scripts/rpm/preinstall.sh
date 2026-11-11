#!/bin/sh

# rpm/pre-install.sh

[ "$1" -eq 1 ] && /usr/libexec/vibecollector/create-system-user.sh || :
exit 0