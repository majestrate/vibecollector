#!/bin/sh
# create-system-user.sh: used to create user and group for vibecollector
set -e

me=$(id -u)
test "$me" = "0" || ( echo "This script must be run as root. (failure: uid=$me)" ; exit 1; )

have() { command -v "$1" >/dev/null 2>&1; }

add_member() {
    user=$1 grp=$2
    if have systemd-sysusers; then
          return 0
    fi
    getent group "$grp" >/dev/null 2>&1 || return 0   # group not ours; skip
    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx "$grp"; then
        return 0                                       # already a member
    fi
    if have usermod; then
        usermod -aG "$grp" "$user"
    elif have gpasswd; then
        gpasswd -a "$user" "$grp" >/dev/null
    elif have adduser; then
        adduser "$user" "$grp" 2>/dev/null || addgroup "$user" "$grp"
    else
      echo "no way to add user to group"; return 1
    fi
}

create_group() {
    groupname="$1"
    if have systemd-sysusers; then
      return 0
    elif have groupadd ; then
      getent group "$groupname" >/dev/null 2>&1 || groupadd -r "$groupname"
    elif have addgroup ; then
      addgroup -S "$groupname" 2>/dev/null
    else
      echo "no way to add group" ; return 1
    fi
}

create_system_user() {
    name="$1"
    groupname="$2"
    home=/var/lib/vibecollector
    desc="Vibecollector Daemon User"

    # Already there? nothing to do. getent is the portable check.
    if ( getent passwd "$name" >/dev/null 2>&1 && getent group "$groupname" 2>&1 ) ; then
        return 0
    fi

    if have systemd-sysusers; then
        systemd-sysusers /usr/lib/sysusers.d/vibecollector.conf
    elif have adduser && adduser --version 2>/dev/null | grep -qi 'debian'; then
        # Debian/Ubuntu adduser: system uid, no password, nologin
        adduser --system --quiet \
                --home "$home" --no-create-home \
                --shell /usr/sbin/nologin \
                --gecos "$desc" "$name"
    elif have useradd; then
        # RHEL/Fedora/SUSE fallback
        useradd -r "$name" -d "$home" -s /usr/sbin/nologin \
                -c "$desc" -M "$name"
    elif have addgroup; then
        # Alpine/busybox
        adduser -S -D -H -h "$home" -s /sbin/nologin -G "$name" -g "$desc" "$name"
    else
        echo "no way to create user" >&2
    fi
}
user=_vibecollector
group=vibecollector-data
create_group "$group"
create_system_user "$user" "$group"
add_member "$user" "$group"