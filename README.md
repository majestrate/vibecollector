# Vibecollector

A MASSIVELY (multiplayer online?) vibecoded Netflow Collector with OAUTH gated REST API and react+vite webui.

## Building

Requirements:

* go >= 1.27
* [nfpm](https://nfpm.goreleaser.com/docs/install/)

To make a deb and rpm package do the following:

    $ make package

If you do not want to install nfpm you can build it manually:

    $ make compile

Then set it up:

    $ PREFIX=$HOME/.local/share/vibecollector make install
    $ cd $HOME/.local/share/vibecollector
    $ mkdir -p conf
    $ [ -f conf/vibecollector.toml ] || ./bin/vibecollector-genconf > conf/collector.toml
    $ [ -n $EDITOR ] && $EDITOR conf/collector.toml
    $ [ -z $EDITOR ] && ( echo "open $PWD/conf/collector.toml in a text editor and make sure it looks right" ; exit 1 )

Then after the configuration looks fine (defaults work out of the box) run:

    $ cd $HOME/.local/share/vibecollector
    $ ./bin/vibecollector -config ./conf/collector.toml