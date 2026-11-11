# rpm/postinstall.sh
if [ $1 -eq 1 ]; then           # fresh install only
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl preset vibecollector.service >/dev/null 2>&1 || :
    systemctl start vibecollector.service >/dev/null 2>&1 || :
fi