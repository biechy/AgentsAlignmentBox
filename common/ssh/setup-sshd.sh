#!/bin/bash
# Prepare sshd for one login user: persistent host key, authorized keys from
# AAB_SSH_PUBKEY (one or more public keys separated by ';'), optional password from
# AAB_SSH_PASSWORD. Runs as root in the container entrypoint.
set -euo pipefail
user=$1

mkdir -p /etc/ssh/keys /etc/aab /run/sshd
[ -s /etc/ssh/keys/ssh_host_ed25519_key ] || \
  ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/keys/ssh_host_ed25519_key

: > /etc/aab/authorized_keys
IFS=';' read -ra keys <<< "${AAB_SSH_PUBKEY:-}"
for k in "${keys[@]}"; do
  k=$(echo "$k" | sed 's/^ *//; s/ *$//')
  [ -n "$k" ] && echo "$k" >> /etc/aab/authorized_keys
done
chmod 644 /etc/aab/authorized_keys

if [ -n "${AAB_SSH_PASSWORD:-}" ]; then
  echo "$user:$AAB_SSH_PASSWORD" | chpasswd
  pw=yes
else
  usermod -p '*' "$user"        # key-only account (not locked for sshd)
  pw=no
fi
printf 'AllowUsers %s\nPasswordAuthentication %s\n' "$user" "$pw" > /etc/ssh/sshd_config.d/00-auth.conf

if [ ! -s /etc/aab/authorized_keys ] && [ "$pw" = no ]; then
  echo "[aab] WARNING: no SSH key (AAB_SSH_PUBKEY) and no password (AAB_SSH_PASSWORD) in .env:" \
       "nobody can log in to $user over SSH." >&2
fi
