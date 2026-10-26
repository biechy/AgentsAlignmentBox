#!/bin/sh
# One-shot `init` service (runs as root, then exits): generate on first start the
# database passwords and the dashboard's launcher SSH key. Each file is readable only
# by the service that needs it (owner uid) and by Postgres (group 70), never by the
# sandbox, which does not mount this volume.
set -eu
D=/run/aab-secrets
mkdir -p "$D" /launcher-pub
chmod 0755 "$D"

gen() {  # name owner-uid
  f="$D/$1.pw"
  [ -s "$f" ] || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$f"
  chown "$2:70" "$f"
  chmod 0440 "$f"
}
gen db_admin 70     # postgres superuser
gen proxy 1001      # proxy  -> proxy_writer
gen monitor 1002    # monitor -> monitor_reader
gen web 1003        # web    -> web_operator

if [ ! -s "$D/launcher_key" ]; then
  ssh-keygen -q -t ed25519 -N '' -C aab-dashboard-launcher -f "$D/launcher_key"
fi
chown 1003:1003 "$D/launcher_key"
chmod 0400 "$D/launcher_key"
cp "$D/launcher_key.pub" /launcher-pub/launcher.pub
chmod 0644 /launcher-pub/launcher.pub
echo "[aab] secrets ready"
