sudo bash -c '{
echo "=== HOSTNAME ==="
hostnamectl

echo "=== USERS ==="
cat /etc/passwd

echo "=== GROUPS ==="
cat /etc/group

echo "=== POSTFIX CONFIGURATION ==="
postconf -n

echo "=== DOVECOT CONFIGURATION ==="
doveconf -n

echo "=== RUNNING SERVICES ==="
systemctl list-units --type=service --state=running

echo "=== LISTENING PORTS ==="
ss -tulpn

echo "=== CRON JOBS ==="
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/

echo "=== MAIL DIRECTORIES ==="
ls -lah /var/mail/
ls -lah /var/vmail/
ls -lah /home/*/Maildir/

echo "=== FIREWALL ==="
ufw status verbose
iptables-save
nft list ruleset

echo "=== NETWORK CONFIGURATION ==="
ip addr
ip route

echo "=== SUID BINARIES ==="
find / -type f -perm -4000 2>/dev/null

echo "=== SUDO USERS ==="
getent group sudo

} > /root/mail-enumeration.txt 2>&1'
