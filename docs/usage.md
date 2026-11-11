# End User Documentation

## Building

Requirements:

* go >= 1.27
* [nfpm](https://nfpm.goreleaser.com/docs/install/)

To make a deb and rpm package do the following:

    $ make package

If you do not want to install nfpm you can build it manually:

    $ make compile

## Installing

### Deb / RPM

If you used `make package` to build a deb and rpm install the package of your choice with your package manager.

### Manual

See `usage` section [here](#manual-setup-cite)

## Usage

### Deb / RPM

If you want a fully random clientId and clientSecret run the following:

    $ vibecollector-manage add -gen-id -gen-secret

If you want a specific clientId (in this case `username`) run the following:

    $ vibecolector-manage add -id username -gen-secret

The user running `vibecollector-manage` must be allowed to run `sudo -u _vibecollector /usr/libexec/vibecollector/_wrapper.sh`

Otherwise, the command needs root access as it assumes the user `_vibecollector` when doing any actions.

The webui is at http://127.0.0.1:8080/ by default.

Configuration is at `/etc/vibecollector.toml`.

Configuration changes require daemon restart (for now):

    $ sudo systemctl restart vibecollector

Use an oauth credential you created to authorize yourself access to it.

### Manual setup

<span id="manual-setup-cite" />

Run a fresh build:

    $ make clean compile

Then install and set it up:

    $ PREFIX=$HOME/.local/share/vibecollector make install
    $ cd $HOME/.local/share/vibecollector
    $ [ -f vibecollector.toml ] || ./bin/vibecollector-genconf > vibecollector.toml
    $ [ -n $EDITOR ] && $EDITOR vibecollector.toml
    $ [ -z $EDITOR ] && ( echo "open $PWD/vibecollector.toml in a text editor and make sure it looks right" ; exit 1 )

Then after the configuration looks fine (defaults work out of the box) run:

    $ cd $HOME/.local/share/vibecollector
    $ ./bin/vibecollector

Add an initial oauth user:

    $ ./bin/vibecollector-manage add -id username -secret password

You can generate a random user credential by running:

    $ ./bin/vibecollector-manage add -gen-id -gen-secret

The web ui is at http://127.0.0.1:8080/

Use the username and password you just created to log into the webui.