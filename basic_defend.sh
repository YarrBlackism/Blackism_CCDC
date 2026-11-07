#!/bin/bash
ALLOW_PORTS=(25 110 143 443 587 993)
BACKUP_DIR="/root/hardening-backups/$(date +%Y%m%d-%H%M%S)"
cat << 'EOF'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡿⠇⠀⠀⠀⠀⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⡸⣞⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠃⠀⠀⠀⢀⣧⢿⣽⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⣼⣞⡿⣞⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠀⠀⠀⣰⣟⢾⣽⢫⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣠⢤⣶⡻⣞⣿⣺⢯⣽⣳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣄⡀⠀⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⣀⣠⣤⣿⣽⣻⢾⣽⣷⣾⣽⣻⣞⣷⣳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣶⣄⡀⠀⠀⠀⣉⣲⣴⢶⣞⡿⣽⣞⡷⣯⢿⡽⣞⣿⠟⠋⠁⠉⠈⠳⣟⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⢶⣾⣿⡽⣯⣟⡾⣽⡷⣯⣟⡽⡾⣽⡯⠁⠀⠀⠀⠀⠀⠀⢮⣭⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢞⣿⣿⢯⡿⣿⣯⣟⣷⣯⢿⣳⣟⡷⣽⣼⣻⣽⠀⠀⠀⠀⠀⠀⠀⢀⣼⡯⡗⠋⠤⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⣿⣿⣯⣽⣾⣿⣾⣗⡿⣯⡷⣯⣟⡷⣞⣼⣿⣀⠀⠀⠀⠀⢀⣠⡿⣏⡗⠈⠐⠈⠅⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠛⠏⠉⠉⠽⢟⢿⣿⣿⣿⣿⣷⣻⢾⡽⣞⡷⠄⡹⣶⢿⣻⢿⣻⡽⢯⣼⢦⠶⠁⠈⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣯⠇⠀⠀⠀⠀⠀⠁⣽⣿⣿⣿⣷⣯⣿⣽⣛⡦⠀⠀⢩⣿⣹⢯⣷⢻⣟⠺⢣⡖⣘⠤⠓⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⡃⠁⠀⠀⠀⢀⣤⣾⣟⢿⣻⣿⣿⣟⡾⣽⡳⠄⠎⢳⣯⢯⣟⡾⢯⣞⣯⣓⠉⢀⠀⠀⡄⢢⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣷⣷⣶⣳⣶⣺⣿⣿⣳⢯⣟⣿⣿⣳⢯⠛⠅⠃⠀⠀⣴⣿⡿⣬⢶⠾⠙⣊⣥⠾⡒⠊⢁⢠⠣⣌⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⡽⣾⡽⣯⣟⣿⡿⣯⣿⣿⣾⢿⣿⠳⢏⣈⢠⠀⠀⣰⢿⡿⣽⣉⡶⠌⠋⠉⣀⡀⠁⠀⠀⠀⣘⡐⣂⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣽⣳⣟⣳⣟⣾⣽⣿⣿⣿⣿⣿⣦⣜⡻⡽⠆⠧⣴⡟⣯⢟⡳⣭⠲⠄⠐⠀⠀⠀⠈⠁⠉⠑⢊⡕⢃⠄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣾⣿⣯⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣾⢧⠀⠹⠾⡵⡞⡽⢢⣃⠐⠀⠀⠄⡐⠀⠀⠀⡘⢦⠘⣌⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠹⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢯⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠒⡈⠀⡀⠄⡑⠢⣉⠴⣈⣆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢯⣏⡴⣶⣵⣢⢤⢠⡀⡄⢠⠐⡰⢌⡱⠀⡁⡀⠆⡥⠆⡥⣛⡽⣾
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠔⠉⠀⠀⢽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣼⣻⢷⣯⡽⣞⣷⣻⡼⣡⢋⡔⠣⠜⡐⢐⠠⡓⣤⣙⣲⣽⣻⢷
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡿⣽⣞⣷⣻⡴⣣⢜⡱⣊⡕⣊⠠⡙⡰⣭⢷⣯⣿⢿
EOF
echo "----------------------------------------------------------------------------"

if [ "$EUID" -ne 0 ]; then
    echo "use sudo"
    exit 1
fi


command -v sshd >/dev/null && mkdir -p /run/sshd

ask() {
    local reply
    read -r -p "$1 (y/n): " reply
    [[ "$reply" == [Yy] ]]
}
backup() {
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    cp -p --parents "$1" "$BACKUP_DIR"
}

restore() {
    cp -p "$BACKUP_DIR$1" "$1"
}

section() {
    printf '\n===== %s =====\n' "$1"
}


echo "starting basic enumeration of mail server"

section "SUID/SGID binaries"
find / -xdev -perm /6000 -type f -exec ls -la {} + 2>/dev/null

section "Postfix settings"
postconf -n | grep -E 'mail|smtp|relay|myhostname|mydomain'

section "World-writable files"
find / -xdev -type f -perm -0002 -print 2>/dev/null

section "Cron jobs"
ls -la /etc/cron*
ls -laR /var/spool/cron 2>/dev/null
while IFS=: read -r user _; do
    if ct=$(crontab -u "$user" -l 2>/dev/null); then
        echo "--- crontab for $user ---"
        echo "$ct"
    fi
done < /etc/passwd

section "Open ports"
ss -tulnp



harden_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then
        echo "ufw isn't installed (apt install ufw) - skipping"
        return 1
    fi
    echo "Starting firewall hardening..."

    local ssh_port port proc
    ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
    ssh_port=${ssh_port:-22}

    ufw allow "$ssh_port/tcp"
    for port in "${ALLOW_PORTS[@]}"; do
        ufw allow "$port/tcp"
    done

    for port in $(ss -Htln | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' \
                  | sed -E 's/.*:([0-9]+)$/\1/' | sort -un); do
        [[ " $ssh_port ${ALLOW_PORTS[*]} " == *" $port "* ]] && continue
        proc=$(ss -Htlnp "sport = :$port" | grep -oP 'users:\(\("\K[^"]+' | head -n1)
        if ask "Port $port (${proc:-unknown process}) is listening but would be blocked. Allow it?"; then
            ufw allow "$port/tcp"
        fi
    done

    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    ufw status numbered
    echo "Review the rules above. Remove any you didn't add with: ufw delete <number>"
}

harden_cron() {
    echo "Starting cron hardening..."
    chown root:root /etc/crontab
    chmod 600 /etc/crontab
    local d
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly /etc/cron.d; do
        [ -d "$d" ] || continue
        chown root:root "$d"
        chmod 750 "$d"
    done
    echo "done"
}

harden_postfix() {
    if [ ! -d /etc/postfix ]; then
        echo "/etc/postfix not found - is Postfix installed? skipping"
        return 1
    fi
    echo "Starting Postfix hardening..."
    backup /etc/postfix/main.cf

    chown root:root /etc/postfix /etc/postfix/main.cf /etc/postfix/master.cf
    chmod 755 /etc/postfix
    chmod 644 /etc/postfix/main.cf /etc/postfix/master.cf
    chmod 755 /etc/postfix/postfix-script* 2>/dev/null
    chmod 755 /var/spool/postfix


    grep -rlE --include='*.cf' '^[[:space:]]*(password|bind_pw)[[:space:]]*=' /etc/postfix 2>/dev/null |
    while read -r f; do
        chown root:postfix "$f"
        chmod 640 "$f"
        echo "  locked down $f"
    done

    local f
    for f in /var/log/mail*; do
        [ -f "$f" ] || continue
        id syslog >/dev/null 2>&1 && chown syslog:adm "$f"
        chmod 640 "$f"
    done

    postconf -e "default_process_limit = 100"
    postconf -e "smtpd_client_connection_count_limit = 10"
    postconf -e "smtpd_client_connection_rate_limit = 30"
    postconf -e "queue_minfree = 20971520"
    postconf -e "header_size_limit = 51200"
    postconf -e "message_size_limit = 10485760"
    postconf -e "smtpd_recipient_limit = 100"
    if [ -n "$SCORER_IP" ]; then
        postconf -e "smtpd_client_event_limit_exceptions = \$mynetworks, $SCORER_IP"
    fi
    
    if postfix check; then
        postfix reload 2>/dev/null || systemctl restart postfix
        echo "done"
    else
        echo "postfix check failed - restored the old main.cf, Postfix NOT reloaded"
        restore /etc/postfix/main.cf
        return 1
    fi
}

harden_ssh() {
    local cfg=/etc/ssh/sshd_config f
    if [ ! -f "$cfg" ]; then
        echo "$cfg not found - skipping"
        return 1
    fi
    if [ -z "$(getent group sudo | cut -d: -f4)" ]; then
        echo "WARNING: nobody is in the sudo group. If you only log in as root, this locks you out."
        ask "Continue anyway?" || return 1
    fi
    echo "Disabling root SSH login..."

    local files=("$cfg" /etc/ssh/sshd_config.d/*.conf)
    for f in "${files[@]}"; do
        [ -f "$f" ] || continue
        backup "$f"
        sed -i -E 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/I' "$f"
    done

    if ! grep -qiE '^PermitRootLogin' "$cfg"; then
        sed -i '1i PermitRootLogin no' "$cfg"
    fi

    if ! sshd -t; then
        echo "sshd config test failed - restored the backups, SSH left as it was"
        for f in "${files[@]}"; do
            [ -f "$BACKUP_DIR$f" ] && restore "$f"
        done
        return 1
    fi

    if systemctl is-active --quiet ssh; then
        systemctl restart ssh
    elif systemctl is-active --quiet sshd; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh.socket; then
        echo "SSH is socket-activated - the change applies to new connections"
    else
        echo "WARNING: couldn't find a running SSH service - restart it manually"
    fi
    echo "Effective setting: $(sshd -T 2>/dev/null | grep -i '^permitrootlogin')"
}

echo
ask "Would you like to harden the firewall?" && harden_firewall
ask "Would you like to harden cron?" && harden_cron
ask "Would you like to harden the Postfix config?" && harden_postfix
ask "Would you like to disable root SSH login?" && harden_ssh

echo
echo "Finished."
[ -d "$BACKUP_DIR" ] && echo "Backups of changed configs are in $BACKUP_DIR"
