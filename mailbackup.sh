
#!/bin/bash

# Ubuntu Mail Server Backup
# Postfix + Dovecot

set -Eeuo pipefail
umask 077

BACKUP_DIR="/var/backups/mail-server"
RETENTION_DAYS=7

# Set to 1 if your mail server uses MariaDB/MySQL
BACKUP_DATABASES=0

# Require root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run this script with sudo."
    exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Prevent overlapping backups
exec 9>/run/lock/mailserver-backup.lock
flock -n 9 || {
    echo "Another backup is already running."
    exit 1
}

DATE=$(date +%Y-%m-%d_%H-%M-%S)
ARCHIVE="$BACKUP_DIR/mailserver-$DATE.tar.gz"
TEMP_ARCHIVE=$(mktemp "$BACKUP_DIR/.partial.XXXXXX")
WORK_DIR=$(mktemp -d "$BACKUP_DIR/.work.XXXXXX")

cleanup() {
    rm -f -- "$TEMP_ARCHIVE"
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

echo "================================"
echo "Ubuntu Mail Server Backup"
echo "Date: $(date)"
echo "================================"

# Mail server configuration and data
PATHS=(
    /etc/postfix
    /etc/dovecot
    /etc/aliases
    /etc/mailname
    /etc/opendkim
    /etc/spamassassin
    /etc/rspamd
    /etc/roundcube
    /etc/letsencrypt
    /etc/ssl/private
    /var/mail
    /var/spool/mail
    /var/vmail
    /srv/vmail
    /var/lib/dovecot
)

# Include home-directory Maildir mailboxes
for path in /home/*/Maildir; do
    if [[ -d "$path" ]]; then
        PATHS+=("$path")
    fi
done

# Add only existing paths
BACKUP_PATHS=()

for path in "${PATHS[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
        BACKUP_PATHS+=("${path#/}")
        echo "[+] Including: $path"
    fi
done

if [[ ${#BACKUP_PATHS[@]} -eq 0 ]]; then
    echo "ERROR: No backup paths found."
    exit 1
fi

# Optional SQL database backup
DB_ARGS=()

if [[ "$BACKUP_DATABASES" -eq 1 ]]; then
    echo "[+] Backing up databases..."

    if command -v mariadb-dump >/dev/null; then
        DUMP_CMD=mariadb-dump
    elif command -v mysqldump >/dev/null; then
        DUMP_CMD=mysqldump
    else
        echo "ERROR: Database dump tool not found."
        exit 1
    fi

    "$DUMP_CMD" --all-databases \
        --single-transaction \
        --routines --events --triggers \
        > "$WORK_DIR/databases.sql"

    DB_ARGS=(-C "$WORK_DIR" databases.sql)
fi

# Create compressed backup
echo "[+] Creating backup archive..."

tar --create --gzip \
    --acls --xattrs --numeric-owner \
    --file="$TEMP_ARCHIVE" \
    -C / "${BACKUP_PATHS[@]}" \
    "${DB_ARGS[@]}"

# Verify archive before saving
echo "[+] Verifying backup..."
tar -tzf "$TEMP_ARCHIVE" > /dev/null

mv -- "$TEMP_ARCHIVE" "$ARCHIVE"

# Generate checksum
(
    cd "$BACKUP_DIR"
    sha256sum "$(basename "$ARCHIVE")" \
        > "$(basename "$ARCHIVE").sha256"
)

# Remove old backup archives and checksums
echo "[+] Removing old backups..."

find "$BACKUP_DIR" -maxdepth 1 -type f \
    \( -name 'mailserver-*.tar.gz' \
    -o -name 'mailserver-*.tar.gz.sha256' \) \
    -mtime +"$RETENTION_DAYS" -delete

echo "================================"
echo "[SUCCESS] Backup completed!"
echo "Location: $ARCHIVE"
du -h "$ARCHIVE"
echo "================================"
