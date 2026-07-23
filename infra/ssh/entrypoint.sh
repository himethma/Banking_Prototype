#!/bin/sh
set -eu

user_name="${SSH_USER:-backup}"
mode="${SSH_MODE:-sftp}"

if ! id "$user_name" >/dev/null 2>&1; then
  adduser -D -u 10001 -h "/home/$user_name" -s /bin/ash "$user_name"
fi
# Keep the account eligible for public-key authentication. Password login remains
# impossible because sshd disables it and rejects empty passwords below.
passwd -d "$user_name" >/dev/null 2>&1
mkdir -p "/home/$user_name/.ssh"
cp /bootstrap/backup_ssh_key.pub "/home/$user_name/.ssh/authorized_keys"
chmod 0700 "/home/$user_name/.ssh"
chmod 0600 "/home/$user_name/.ssh/authorized_keys"
chown -R "$user_name:$user_name" "/home/$user_name"
cat >/etc/ssh/sshd_config <<EOF
Port 2222
Protocol 2
HostKey /bootstrap/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
AllowUsers $user_name
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF

if [ "$mode" = "sftp" ]; then
  mkdir -p /srv/storage
  chown root:root /srv
  chmod 0755 /srv
  chown "$user_name:$user_name" /srv/storage
  cat >>/etc/ssh/sshd_config <<EOF
Match User $user_name
  ChrootDirectory /srv
  ForceCommand internal-sftp -u 077
  AllowTcpForwarding no
EOF
else
  chown "$user_name:$user_name" /var/log/bastion
fi

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
