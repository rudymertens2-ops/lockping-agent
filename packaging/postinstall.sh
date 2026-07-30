#!/bin/sh
# Getoond na rpm/deb-installatie: de drie stappen naar een werkende agent.
cat <<'EOF'

  LockPing agent geïnstalleerd. Zo koppel je je telefoon:

    1.  lockping-agent run -pair
        (toont een QR-code + koppelcode, 5 minuten geldig)
    2.  Open https://app.lockping.rm-worx.be en kies "PC koppelen".
    3.  Stop met Ctrl+C en schakel de agent daarna vast in:
        systemctl --user enable --now lockping-agent

  Documentatie: /usr/share/doc/lockping-agent/README.md

EOF
exit 0
