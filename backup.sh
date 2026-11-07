#!/usr/bin/env bash

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

VERSION="1.0"
SELF="${BASH_SOURCE[0]:-ccdc-mail.sh}"
OUTDIR="/linuxEnnum"
TS="$(date +%Y%m%d-%H%M%S)"
EXPECTED_TCP="22 25 80 110 143 443 993 995"
EXPECTED_UDP="68 123 323 546"
WATCH_SEC=15
LOG=""
RED=0
YEL=0
FLAG_PIDS=()
SUS_USERS=()          # entries look like "name|reason"
OWNED_LIST=""
declare -A ALLOWED=()
HAVE_ALLOW=0

# Process names that should never own a network connection or a socket on stdin
STRONG_RE='^((ba|da|z|k|c|tc|fi|a|mk|y)?sh|nc|ncat|netcat|nc\.openbsd|nc\.traditional|socat|telnet|busybox|openssl|script)$'
INTERP_RE='^(python[0-9.]*|perl[0-9.]*|php[0-9.]*|ruby[0-9.]*|lua[0-9.]*|node|nodejs|[gm]?awk|tclsh[0-9.]*|expect)$'
# Text that shows up in reverse shells and droppers
REVSHELL_RE='/dev/(tcp|udp)/|\bnc(at)?\b[^|;]*[[:space:]]-[ec]\b|\bsocat\b|\b(ba)?sh -i\b|mkfifo|0<&[0-9]|exec [0-9]+<>|fsockopen|socket\.socket|pty\.spawn|IO::Socket|TCPSocket|\b(curl|wget)\b[^|]*\|[[:space:]]*(ba)?sh\b|base64 (-d|--decode)|LD_PRELOAD'
# PHP web-shell fingerprints
WEBSHELL_RE='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(system|passthru|shell_exec|popen|proc_open|assert|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\('

# Paths that differ between Ubuntu and Rocky-style installs
MAILLOG=/var/log/mail.log;                 [[ -f $MAILLOG ]] || MAILLOG=/var/log/maillog
RC_CFG=/etc/roundcube/config.inc.php;      [[ -f $RC_CFG ]]  || RC_CFG=/etc/roundcubemail/config.inc.php
RC_LOGDIR=/var/log/roundcube;              [[ -d $RC_LOGDIR ]] || RC_LOGDIR=/var/log/roundcubemail
WEBUSER=www-data;                          id www-data >/dev/null 2>&1 || WEBUSER=apache

if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_Y=$'\e[1;33m'; C_G=$'\e[32m'; C_B=$'\e[1;36m'; C_N=$'\e[0m'
else
  C_R=""; C_Y=""; C_G=""; C_B=""; C_N=""
fi

# ----------------------------------------------------------------------------- helpers
hdr()    { printf '\n%s===== %s =====%s\n' "$C_B" "$*" "$C_N"; }
bad()    { RED=$((RED+1)); printf '%s[!!] %s%s\n' "$C_R" "$*" "$C_N"; }
warn()   { YEL=$((YEL+1)); printf '%s[!]  %s%s\n' "$C_Y" "$*" "$C_N"; }
ok()     { printf '%s[ok] %s%s\n' "$C_G" "$*" "$C_N"; }
info()   { printf '     %s\n' "$*"; }
indent() { sed 's/^/       /'; }
have()   { command -v "$1" >/dev/null 2>&1; }
ask() {   # default is No; reads the terminal so it also works when piped
  local a=""
  read -r -p "${C_Y}[?]  $* [y/N] ${C_N}" a </dev/tty 2>/dev/tty || return 1
  [[ $a =~ ^[Yy] ]]
}
cmdline_of() { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | cut -c1-200; }
user_of()    { ps -o user= -p "$1" 2>/dev/null | tr -d ' '; }
pkg_installed() {
  if have dpkg-query; then [[ $(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null) == installed ]]
  else have rpm && rpm -q "$1" >/dev/null 2>&1; fi
}
is_loopback() { [[ $1 =~ ^(127\.|\[::1\]$|::1$|\[::ffff:127\.) || $1 == *%lo ]]; }

load_owned() {
  [[ -n $OWNED_LIST && -s $OWNED_LIST ]] && return 0
  OWNED_LIST="$(mktemp)"
  if [[ -d /var/lib/dpkg/info ]]; then cat /var/lib/dpkg/info/*.list > "$OWNED_LIST" 2>/dev/null
  elif have rpm; then rpm -qal > "$OWNED_LIST" 2>/dev/null; fi
}
owned() {   # is this path installed by a package?
  load_owned
  [[ -s $OWNED_LIST ]] || return 0     # no package database: don't guess
  local p="$1" alt="$1"
  case "$p" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib32/*|/usr/lib64/*|/usr/libx32/*) alt="${p#/usr}" ;;
    /bin/*|/sbin/*|/lib/*|/lib32/*|/lib64/*|/libx32/*) alt="/usr$p" ;;
  esac
  grep -qxF -e "$p" -e "$alt" "$OWNED_LIST"
}
cleanup() { [[ -n $OWNED_LIST ]] && rm -f "$OWNED_LIST"; }
trap cleanup EXIT

need_root() { [[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $SELF $1"; exit 1; }; }

start_log() {
  mkdir -p "$OUTDIR" && chmod 700 "$OUTDIR"
  LOG="$OUTDIR/$1-$TS.log"
  exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' >> "$LOG")) 2>&1
  printf '%sccdc-mail.sh %s | mode %s | %s | %s%s\n' "$C_B" "$VERSION" "$1" "$(hostname)" "$(date)" "$C_N"
}

summary() {
  hdr "Summary"
  printf '%s%d red%s and %s%d yellow%s findings. Log: %s\n' "$C_R" "$RED" "$C_N" "$C_Y" "$YEL" "$C_N" "$LOG"
  info "Red = act now. Yellow = read it and decide. ${1:-This mode changed nothing.}"
}

# ----------------------------------------------------------------------------- system
sysinfo() {
  hdr "System"
  local os="unknown"
  [[ -r /etc/os-release ]] && os="$(. /etc/os-release; echo "$PRETTY_NAME")"
  info "Host: $(hostname -f 2>/dev/null || hostname)   OS: $os   Kernel: $(uname -r)"
  info "IPs: $(hostname -I 2>/dev/null)   Up: $(uptime -p 2>/dev/null)"
  info "Logged in now:"; who 2>/dev/null | indent
}

# ----------------------------------------------------------------------------- accounts
check_accounts() {
  hdr "Accounts"
  local name pass uid gid gecos home shell login line f g members acct hash s v
  local -A uid_of=() seen_home=()
  local -a humans=() shellers=()

  while IFS=: read -r name pass uid gid gecos home shell; do
    [[ -z $name || $name == \#* ]] && continue
    [[ $uid =~ ^[0-9]+$ ]] || { warn "Malformed /etc/passwd line for $name"; continue; }
    uid_of[$name]="$uid"
    login=1
    case "$shell" in */nologin|*/false|*/sync|*/shutdown|*/halt|"") login=0 ;; esac
    if [[ $uid == 0 && $name != root ]]; then
      bad "UID 0 account besides root: $name ($shell)"; SUS_USERS+=("$name|uid 0, root-equivalent")
    fi
    (( uid >= 1000 && uid < 65534 )) && humans+=("$name")
    if (( login )); then
      shellers+=("$name")
      (( uid > 0 && uid < 1000 )) && { warn "System account with a login shell: $name (uid $uid, $shell)"; SUS_USERS+=("$name|system account with a shell"); }
    fi
    if (( HAVE_ALLOW )) && [[ $name != root && $uid != 65534 ]] && (( login || uid >= 1000 )) && [[ -z ${ALLOWED[$name]:-} ]]; then
      bad "Not on the authorized list: $name (uid $uid, $shell)"; SUS_USERS+=("$name|not on the authorized list")
    fi
  done < /etc/passwd
  info "Human accounts (uid >= 1000): ${humans[*]:-none}"
  info "Accounts with a login shell: ${shellers[*]:-none}"

  while IFS=: read -r acct hash _; do
    [[ -z $acct ]] && continue
    if [[ -z $hash ]]; then
      bad "Empty password, anyone can log in: $acct"; SUS_USERS+=("$acct|empty password")
    elif [[ $hash == \$* && $acct != root ]] && (( ${uid_of[$acct]:-1000} < 1000 )); then
      warn "System account has a real password: $acct"
    fi
  done < /etc/shadow

  line="$(cut -d: -f3 /etc/passwd | sort | uniq -d | tr '\n' ' ')"
  [[ -n ${line// /} ]] && bad "Duplicate UIDs: $line"

  for g in sudo admin wheel; do
    getent group "$g" >/dev/null || continue
    members="$(getent group "$g" | cut -d: -f4)"
    info "Group $g (can sudo): ${members:-(empty)}"
  done
  while IFS= read -r line; do
    if [[ $line == *NOPASSWD* ]]; then warn "sudoers NOPASSWD: $line"; else info "sudoers: $line"; fi
  done < <(grep -HnE '^[[:space:]]*[^#[:space:]]' /etc/sudoers /etc/sudoers.d/* 2>/dev/null |
           grep -vE ':[0-9]+:[[:space:]]*(Defaults|@include|#include)')

  while IFS=: read -r name _ _ _ _ home _; do
    [[ -n $home && -z ${seen_home[$home]:-} ]] || continue
    seen_home[$home]=1
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -s $f ]] || continue
      warn "SSH keys for $name in $f (each one is a way in; verify them):"
      ssh-keygen -lf "$f" 2>/dev/null | indent
    done
    [[ -e $home/.ssh/rc ]] && bad "$home/.ssh/rc runs on every SSH login for $name: $(head -c 150 "$home/.ssh/rc")"
  done < /etc/passwd
  [[ -e /etc/ssh/sshrc ]] && bad "/etc/ssh/sshrc runs on every SSH login: $(head -c 150 /etc/ssh/sshrc)"

  if have sshd; then
    s="$(sshd -T 2>&1)"
    if [[ $s != *permitrootlogin* ]]; then
      info "sshd -T could not run: $(head -n1 <<<"$s")"
    else
      for v in permitrootlogin passwordauthentication permitemptypasswords authorizedkeysfile; do
        info "sshd $v: $(awk -v k="$v" '$1==k {$1=""; sub(/^ /,""); print; exit}' <<<"$s")"
      done
      grep -q '^permitemptypasswords yes' <<<"$s" && bad "sshd accepts empty passwords"
      v="$(awk '$1=="authorizedkeysfile" {$1=""; sub(/^ /,""); print; exit}' <<<"$s")"
      [[ $v =~ ^\.ssh/authorized_keys(\ \.ssh/authorized_keys2)?$ ]] || warn "Unusual AuthorizedKeysFile: $v"
      v="$(awk '$1=="authorizedkeyscommand" {print $2; exit}' <<<"$s")"
      [[ -z $v || $v == none ]] || bad "AuthorizedKeysCommand runs a program at every SSH login: $v"
    fi
  fi

  info "Account files last changed (ctime):"
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
    [[ -e $f ]] && info "  $(stat -c '%z' "$f" | cut -c1-19)  $f"
  done
  if have last; then info "Recent logins:"; last -a -n 8 2>/dev/null | grep -vE '^(wtmp|$)' | indent; fi
  if have lastb; then info "Recent failed logins:"; lastb -a -n 8 2>/dev/null | grep -vE '^(btmp|$)' | indent; fi
}

# ----------------------------------------------------------------------------- network
listeners() {   # prints: proto address port process
  have ss || return 0
  local proto loc rest port addr name
  while read -r proto _ _ _ loc _ rest; do
    port="${loc##*:}"; addr="${loc%:*}"
    name="$(grep -oE '"[^"]+"' <<<"$rest" | head -n1 | tr -d '"')"
    printf '%s %s %s %s\n' "$proto" "$addr" "$port" "${name:--}"
  done < <(ss -tulpnH 2>/dev/null) | sort -u
}

established() { # prints: local peer process pid
  have ss || return 0
  local loc peer rest name pid
  while read -r _ _ loc peer rest; do
    while read -r name pid; do
      [[ -n $name ]] && printf '%s %s %s %s\n' "$loc" "$peer" "$name" "$pid"
    done < <(grep -oE '\("[^"]+",pid=[0-9]+' <<<"$rest" | sed -E 's/^\("([^"]+)",pid=([0-9]+)$/\1 \2/' | sort -u)
  done < <(ss -tnpH state established 2>/dev/null)
}

net_findings() {
  local loc peer name pid proto addr port
  while read -r loc peer name pid; do
    if [[ $name =~ $STRONG_RE ]]; then
      bad "Shell/netcat holding a live connection (reverse shell?): $name PID $pid ($(user_of "$pid")) $loc -> $peer : $(cmdline_of "$pid")"
      FLAG_PIDS+=("$pid")
    elif [[ $name =~ $INTERP_RE ]]; then
      warn "Script interpreter holding a live connection: $name PID $pid ($(user_of "$pid")) $loc -> $peer : $(cmdline_of "$pid")"
      FLAG_PIDS+=("$pid")
    fi
  done < <(established)
  while read -r proto addr port name; do
    if [[ $name =~ $STRONG_RE || $name =~ $INTERP_RE ]]; then
      bad "$name is LISTENING on $proto $addr:$port (bind shell?)"; continue
    fi
    is_loopback "$addr" && continue
    if [[ $proto == tcp ]]; then
      if [[ $port == 3306 ]]; then bad "MariaDB/MySQL reachable from the network on $addr:3306"; continue; fi
      [[ " $EXPECTED_TCP " == *" $port "* ]] || warn "Unexpected TCP listener: $addr:$port ($name)"
    else
      [[ " $EXPECTED_UDP " == *" $port "* ]] || warn "Unexpected UDP listener: $addr:$port ($name)"
    fi
  done < <(listeners)
}

check_network() {
  hdr "Network: listeners and live connections"
  have ss || { bad "ss is missing (apt install iproute2); network checks skipped"; return 0; }
  local before=$((RED+YEL))
  net_findings
  (( RED+YEL == before )) && ok "No shells or interpreters on the network, no unexpected listeners"
  info "Listening (proto address port process):"
  listeners | indent
  info "Established TCP (local -> peer, process[pid]):"
  established | awk '{printf "%-26s -> %-26s %s[%s]\n", $1, $2, $3, $4}' | sort -u | indent
}

# ----------------------------------------------------------------------------- processes
proc_findings() {
  local d pid comm exe cmd user fd0 fd1 ppid pcomm
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    [[ $pid == "$$" ]] && continue
    comm="$(cat "$d/comm" 2>/dev/null)" || continue
    [[ -z $comm ]] && continue
    exe="$(readlink "$d/exe" 2>/dev/null)"
    cmd="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | cut -c1-200)"
    user="$(stat -c %U "$d" 2>/dev/null)"
    if [[ $comm =~ $STRONG_RE || $comm =~ $INTERP_RE ]]; then
      fd0="$(readlink "$d/fd/0" 2>/dev/null)"; fd1="$(readlink "$d/fd/1" 2>/dev/null)"
      if [[ $fd0 == socket:* || $fd1 == socket:* ]]; then
        bad "Reverse shell pattern: $comm PID $pid ($user) has a socket as stdin/stdout : $cmd"
        FLAG_PIDS+=("$pid")
      elif [[ $fd0 == /* && -p $fd0 ]]; then
        warn "$comm PID $pid ($user) reads from named pipe $fd0 (mkfifo shell?) : $cmd"
        FLAG_PIDS+=("$pid")
      fi
      ppid="$(awk '/^PPid:/{print $2}' "$d/status" 2>/dev/null)"
      pcomm="$(cat "/proc/$ppid/comm" 2>/dev/null)"
      if [[ $user == "$WEBUSER" || $pcomm =~ ^(apache2|httpd|nginx|lighttpd|php-fpm.*)$ ]]; then
        bad "Shell under the web server (web shell?): $comm PID $pid ($user, parent $pcomm) : $cmd"
        FLAG_PIDS+=("$pid")
      fi
    fi
    case "$exe" in
      /memfd:*)
        bad "Fileless process running from memory (memfd): PID $pid ($user) $exe : $cmd"; FLAG_PIDS+=("$pid") ;;
      /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*)
        bad "Runs from a temp directory: PID $pid ($user) $exe : $cmd"; FLAG_PIDS+=("$pid") ;;
      /home/*|/var/www/*|/var/lib/roundcube/*|/var/mail/*)
        warn "Runs from a user or web directory: PID $pid ($user) $exe : $cmd" ;;
      *" (deleted)")
        warn "Binary deleted from disk: PID $pid ($user) $exe : $cmd (also normal after an upgrade without a restart)" ;;
    esac
    if [[ $cmd == \[* && -n $exe ]]; then
      bad "Disguised as a kernel thread: PID $pid ($user) '$cmd' is really $exe"; FLAG_PIDS+=("$pid")
    fi
  done
}

check_procs() {
  hdr "Processes"
  local before=$((RED+YEL))
  proc_findings
  (( RED+YEL == before )) && ok "No reverse-shell patterns in running processes"
}

# ----------------------------------------------------------------------------- persistence
check_persistence() {
  hdr "Persistence"
  local u line f h path b
  while IFS=: read -r u _; do
    while IFS= read -r line; do
      [[ -z ${line// /} || $line == \#* ]] && continue
      warn "crontab of $u: $line"
    done < <(crontab -l -u "$u" 2>/dev/null)
  done < /etc/passwd

  for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
           /etc/update-motd.d/* /etc/profile.d/* /etc/init.d/* /etc/apt/apt.conf.d/* /etc/sudoers.d/*; do
    [[ -f $f ]] || continue
    case "${f##*/}" in .placeholder|README|20auto-upgrades|90curtin-*|00trustcdrom|00CDMountPoint|60-unminimize) continue ;; esac
    owned "$f" || warn "Not installed by any package (read it): $f"
  done

  for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.socket /etc/systemd/system/*.path; do
    [[ -f $f && ! -L $f ]] || continue
    case "${f##*/}" in snap-*|snap.*) continue ;; esac
    owned "$f" || warn "Custom systemd unit $f: $(grep -hE '^[[:space:]]*Exec' "$f" | tr '\n' ' ' | cut -c1-200)"
  done
  for f in /etc/systemd/system/*.d/*.conf; do
    [[ -f $f ]] || continue
    owned "$f" || warn "systemd drop-in $f: $(grep -hE '^[[:space:]]*Exec' "$f" | tr '\n' ' ' | cut -c1-200)"
  done
  local -a vdirs=(/usr/lib/systemd/system)
  [[ -L /lib || ! -d /lib/systemd/system ]] || vdirs+=(/lib/systemd/system)
  for h in "${vdirs[@]}"; do
    for f in "$h"/*.service "$h"/*.timer "$h"/*.socket; do
      [[ -f $f && ! -L $f ]] || continue
      owned "$f" || bad "Unit in the vendor directory that no package installed: $f"
    done
  done
  while IFS= read -r f; do warn "User-level systemd unit: $f"; done < <(find /root /home -path '*/.config/systemd/user/*' -type f 2>/dev/null)
  if have systemctl; then
    info "Timers (unit -> what it runs):"
    systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $(NF-1), "->", $NF}' | indent
    info "Overridden units (systemd-delta):"
    systemd-delta --no-pager --type=extended,overridden 2>/dev/null | grep -vE '^$|configuration files? found' | indent
  fi

  [[ -s /etc/rc.local ]] && { warn "/etc/rc.local exists:"; grep -vE '^[[:space:]]*(#|$)' /etc/rc.local | indent; }
  [[ -s /etc/ld.so.preload ]] && bad "/etc/ld.so.preload loads a library into every program: $(tr '\n' ' ' < /etc/ld.so.preload)"

  local -a spots=(/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron
                  /etc/systemd/system /etc/rc.local /etc/init.d /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment
                  /etc/update-motd.d /etc/apt/apt.conf.d /etc/sudoers.d /etc/aliases /etc/postfix /etc/ssh/sshrc)
  for h in /root /home/*; do
    for f in .bashrc .bash_profile .bash_login .bash_logout .profile .zshrc .ssh/rc .config/autostart; do
      [[ -e $h/$f ]] && spots+=("$h/$f")
    done
  done
  local -a existing=()
  for f in "${spots[@]}"; do [[ -e $f ]] && existing+=("$f"); done
  while IFS= read -r line; do bad "Reverse-shell pattern: $line"; done < <(grep -rnIsE "$REVSHELL_RE" "${existing[@]}" 2>/dev/null | cut -c1-250)

  while IFS= read -r f; do warn "Executable or hidden item in a temp dir: $f"; done < <(
    find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 \( -type f \( -perm /111 -o -name '.*' \) \) -o \
      \( -type d -name '.*' ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.Test-unix' ! -name '.XIM-unix' \) \
      2>/dev/null | head -n 40)

  while IFS= read -r f; do
    owned "$f" || bad "SUID/SGID file no package installed: $f ($(stat -c '%U %a' "$f"))"
  done < <(find / /home /var /tmp -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort -u)

  if have getcap; then
    while IFS= read -r line; do
      path="${line%% *}"; b="${path##*/}"
      if [[ $b =~ ^(python|perl|php|ruby|node|bash|dash|sh|zsh|vim?|find|tar|gdb|env|less|[gm]?awk|nc|socat)[0-9.]*$ && \
            $line =~ cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|chown|fowner) ]]; then
        bad "Root-level capability on a shell or interpreter: $line"
      else
        info "capability: $line"
      fi
    done < <(getcap -r /usr /opt /home /tmp /var/tmp /srv 2>/dev/null)
  fi

  while IFS= read -r line; do bad "pam_exec in PAM (can capture passwords or run code): $line"; done < <(grep -rnE '^[^#]*pam_exec' /etc/pam.d 2>/dev/null)
  while IFS= read -r line; do bad "pam_permit marked sufficient (any password works): $line"; done < <(grep -rnE '^[^#]*sufficient[[:space:]]+pam_permit' /etc/pam.d 2>/dev/null)
  if [[ -f /etc/pam.d/common-auth ]] && ! grep -qE '^[^#]*pam_deny' /etc/pam.d/common-auth; then
    bad "/etc/pam.d/common-auth has no pam_deny line (wrong passwords may be accepted)"
  fi
}

# ----------------------------------------------------------------------------- integrity
verify_report() {   # reads dpkg --verify / rpm -V lines on stdin; prints findings; returns modified count
  local line path nmod=0 ndoc=0
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    path="${line##* }"
    case "$line" in
      *" c /"*) info "config changed: $path" ;;
      missing*)
        case "$path" in
          /usr/share/doc/*|/usr/share/man/*|/usr/share/info/*|/usr/share/locale/*|/usr/share/lintian/*|/usr/share/doc-base/*) ndoc=$((ndoc+1)) ;;
          *) warn "package file missing: $path" ;;
        esac ;;
      *5*) bad "MODIFIED program file (trojaned tools can hide an attacker): $path"; nmod=$((nmod+1)) ;;
    esac
  done
  (( ndoc )) && info "$ndoc documentation files are missing (normal on minimized images)"
  return "$nmod"
}

check_integrity() {
  hdr "Package integrity"
  local nbad=0 m
  local -a pkgs=()
  if have dpkg-query; then
    mapfile -t pkgs < <(dpkg-query -W -f='${Package} ${db:Status-Status}\n' coreutils procps iproute2 net-tools util-linux \
      findutils grep sed gawk mawk passwd login sudo bash dash openssh-server libpam-modules libpam-modules-bin \
      libpam-runtime cron systemd postfix dovecot-core dovecot-imapd dovecot-pop3d apache2 apache2-bin \
      'libapache2-mod-php*' roundcube-core 2>/dev/null | awk '$2=="installed"{print $1}')
    info "Checking ${#pkgs[@]} packages with dpkg --verify (shows files changed since install)..."
    verify_report < <(dpkg --verify "${pkgs[@]}" 2>/dev/null); nbad=$?
  elif have rpm; then
    info "Checking key packages with rpm -V..."
    verify_report < <(rpm -V coreutils procps-ng iproute util-linux findutils grep sed passwd sudo bash openssh-server pam postfix dovecot httpd 2>/dev/null); nbad=$?
  fi
  (( nbad == 0 )) && ok "No modified program files in those packages"
  while IFS= read -r m; do
    owned "$m" || bad "PAM module no package installed: $m"
  done < <(find /usr/lib /lib64 -maxdepth 3 -path '*/security/*.so' 2>/dev/null)
}

# ----------------------------------------------------------------------------- postfix
smtp_probe() {   # runs inside "timeout bash -c"; never sends DATA, so no mail goes out
  local ip="$1"
  exec 3<>"/dev/tcp/$ip/25" || exit 3
  rd() { local l; while IFS= read -r -t 8 l <&3; do l="${l%$'\r'}"; printf '%s\n' "$l"; [[ $l =~ ^[0-9]{3}([[:space:]]|$) ]] && return 0; done; return 1; }
  rd >/dev/null || exit 4
  printf 'EHLO relay-test.example.net\r\n' >&3; rd >/dev/null
  printf 'MAIL FROM:<probe@example.org>\r\n' >&3; printf 'MAIL %s\n' "$(rd | tail -n1)"
  printf 'RCPT TO:<probe@example.com>\r\n' >&3;  printf 'RCPT %s\n' "$(rd | tail -n1)"
  printf 'RSET\r\n' >&3; rd >/dev/null
  printf 'VRFY root\r\n' >&3; printf 'VRFY %s\n' "$(rd | tail -n1)"
  printf 'QUIT\r\n' >&3; rd >/dev/null
  exec 3>&-
}

smtp_selftest() {
  local ip out mail rcpt vrfy
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n $ip ]] || { info "Relay self-test skipped: no IP address found"; return 0; }
  out="$(timeout 25 bash -c "$(declare -f smtp_probe); smtp_probe $ip" 2>/dev/null)"
  [[ -n $out ]] || { info "Relay self-test: nothing answered on $ip:25"; return 0; }
  mail="$(sed -n 's/^MAIL //p' <<<"$out")"; rcpt="$(sed -n 's/^RCPT //p' <<<"$out")"; vrfy="$(sed -n 's/^VRFY //p' <<<"$out")"
  if [[ $mail != 250* ]]; then info "Relay self-test: MAIL FROM was refused ($mail)"; return 0; fi
  case "$rcpt" in
    250*) bad "OPEN RELAY: $ip accepted mail for an outside domain from a non-localhost address ($rcpt)" ;;
    454*|554*) ok "Not an open relay from $ip ($rcpt)" ;;
    *) info "Relay self-test answer: $rcpt" ;;
  esac
  case "$vrfy" in 502*) ok "VRFY is refused" ;; 25[02]*) warn "VRFY confirms account names ($vrfy)" ;; esac
  info "(The self-test connects from this box's own LAN address, so Postfix doesn't treat it as localhost.)"
}

check_postfix() {
  have postconf || return 0
  hdr "Postfix"
  if postfix status >/dev/null 2>&1; then ok "Postfix is running"; else bad "Postfix is NOT running (check: systemctl status postfix@-)"; fi
  local v n p line
  local -a nets=()
  v="$(postconf -h mynetworks 2>/dev/null)"
  info "mynetworks = $v"
  read -ra nets <<<"${v//,/ }"
  for n in "${nets[@]}"; do
    case "$n" in
      127.0.0.0/8|127.0.0.1|127.0.0.1/32|'[::1]/128'|'[::ffff:127.0.0.0]/104'|'[::1]') ;;
      *) bad "mynetworks trusts $n: anything there can relay mail to any domain" ;;
    esac
  done
  v="$(postconf -h smtpd_relay_restrictions 2>/dev/null)"
  info "smtpd_relay_restrictions = $v"
  if [[ $v =~ (^|[[:space:],])permit($|[[:space:],]) ]]; then bad "smtpd_relay_restrictions contains a bare 'permit'"
  elif [[ $v != *unauth_destination* ]]; then bad "smtpd_relay_restrictions has no reject_unauth_destination"
  else ok "Relay restrictions look normal"; fi
  for p in relayhost transport_maps always_bcc sender_bcc_maps recipient_bcc_maps content_filter smtpd_milters \
           non_smtpd_milters header_checks body_checks virtual_alias_maps; do
    v="$(postconf -nh "$p" 2>/dev/null)"
    [[ -n $v ]] && warn "$p = $v  (mail can be copied, rerouted or rewritten here)"
  done
  v="$(postconf -h default_transport 2>/dev/null)"; [[ $v == error:* ]] && info "default_transport = $v (outbound mail is disabled)"
  if [[ $(postconf -h disable_vrfy_command 2>/dev/null) == yes ]]; then ok "VRFY disabled"; else warn "VRFY enabled (anyone can confirm account names)"; fi
  [[ $(postconf -h smtpd_helo_required 2>/dev/null) == yes ]] || warn "smtpd_helo_required = no"
  v="$(postconf -h smtpd_banner 2>/dev/null)"; [[ $v =~ mail_name|Postfix|Ubuntu|Debian ]] && warn "Banner reveals software: $v"
  v="$(postconf -h allow_mail_to_commands 2>/dev/null)"; [[ $v == *forward* ]] && warn "allow_mail_to_commands = $v (~/.forward files can run programs)"
  while IFS= read -r line; do warn "master.cf override: $line"; done < <(postconf -P 2>/dev/null | grep -E 'restrictions|mynetworks|content_filter|milters')
  while read -r n _ _ _ _ _ _ p line; do
    [[ $p == pipe ]] || continue
    # shellcheck disable=SC2194
    case " maildrop uucp ifmail bsmtp scalemail-backend mailman " in
      *" $n "*) ;;
      *) bad "Non-stock pipe service in master.cf (runs a program for mail): $n $line" ;;
    esac
  done < <(postconf -M 2>/dev/null)
  if [[ -f /usr/share/postfix/master.cf.dist && -f /etc/postfix/master.cf ]]; then
    line="$(diff <(grep -vE '^[[:space:]]*(#|$)' /usr/share/postfix/master.cf.dist) <(grep -vE '^[[:space:]]*(#|$)' /etc/postfix/master.cf) | grep '^[<>]')"
    if [[ -n $line ]]; then warn "master.cf differs from the shipped copy (< shipped, > yours):"; printf '%s\n' "$line" | head -n 20 | indent
    else ok "master.cf matches the shipped copy"; fi
  fi
  if [[ -f /etc/aliases ]]; then
    while IFS= read -r line; do bad "Alias runs a program when mail arrives: $line"; done < <(grep -nE '^[^#].*\|' /etc/aliases)
    while IFS= read -r line; do warn "Alias forwards off the box: $line"; done < <(grep -nE '^[^#][^:]*:.*@' /etc/aliases)
    while IFS= read -r line; do warn "Alias writes mail into a file: $line"; done < <(grep -nE '^[^#][^:]*:[[:space:]]*/' /etc/aliases)
  fi
  while IFS= read -r p; do
    if grep -q '|' "$p" 2>/dev/null; then bad "$p pipes mail into a program: $(head -c 150 "$p")"
    else warn "$p forwards mail: $(head -c 150 "$p")"; fi
  done < <(find /root /home -maxdepth 2 -name '.forward*' -type f 2>/dev/null)
  v="$(postqueue -p 2>/dev/null | tail -n1)"; info "Queue: $v"
  [[ $v =~ in\ ([0-9]+)\ Request ]] && (( BASH_REMATCH[1] > 50 )) && warn "Big mail queue (${BASH_REMATCH[1]} messages): spam or a loop?"
  smtp_selftest
}

# ----------------------------------------------------------------------------- dovecot
check_dovecot() {
  have doveconf || return 0
  hdr "Dovecot"
  local ver v pdb inc f shipped
  ver="$(dovecot --version 2>/dev/null | awk '{print $1}')"
  info "Dovecot $ver"
  if ! doveconf -n >/dev/null 2>&1; then bad "doveconf -n fails: $(doveconf -n 2>&1 >/dev/null | head -n 2)"; return 0; fi
  if pgrep -x dovecot >/dev/null; then ok "Dovecot is running"; else bad "Dovecot is NOT running"; fi
  v="$(doveconf -h ssl 2>/dev/null)"
  case "$v" in required) ok "ssl = required" ;; yes) warn "ssl = yes (TLS offered, not required)" ;; *) bad "ssl = ${v:-?}" ;; esac
  if [[ $ver == 2.4* ]]; then
    v="$(doveconf -h auth_allow_cleartext 2>/dev/null)"
    if [[ $v == no ]]; then ok "Plaintext passwords refused without TLS"; else warn "auth_allow_cleartext = $v"; fi
  else
    v="$(doveconf -h disable_plaintext_auth 2>/dev/null)"
    if [[ $v == yes ]]; then ok "Plaintext passwords refused without TLS"; else warn "disable_plaintext_auth = $v"; fi
  fi
  v="$(doveconf -h auth_verbose_passwords 2>/dev/null)"; [[ -z $v || $v == no ]] || bad "auth_verbose_passwords = $v (passwords end up in the log)"
  if [[ $ver == 2.3* ]]; then v="$(doveconf -h auth_debug_passwords 2>/dev/null)"; [[ $v == yes ]] && bad "auth_debug_passwords = yes (passwords end up in the log)"; fi
  v="$(doveconf -h login_trusted_networks 2>/dev/null)"; [[ -n ${v// /} ]] && warn "login_trusted_networks = $v"
  v="$(doveconf -h first_valid_uid 2>/dev/null)"; (( ${v:-0} < 1000 )) && warn "first_valid_uid = $v (accounts below 1000 can log in to mail)"
  info "protocols =$(doveconf -h protocols 2>/dev/null)"
  pdb="$(doveconf -n 2>/dev/null | awk '/^passdb/{f=1} f{print} f && /^}/{f=0}')"
  info "Password databases:"; printf '%s\n' "$pdb" | indent
  grep -qE 'master[[:space:]]*=[[:space:]]*yes' <<<"$pdb" && bad "A master passdb exists: one password opens every mailbox"
  grep -qE 'driver[[:space:]]*=[[:space:]]*(static|checkpassword)' <<<"$pdb" && bad "passdb uses static or checkpassword (can let anyone in)"
  (( $(grep -c '^passdb' <<<"$pdb") > 1 )) && warn "More than one passdb is active"
  while IFS= read -r inc; do
    case "$inc" in *auth-system.conf.ext*|*auth-deny.conf.ext*) ;; *) bad "Extra login method in 10-auth.conf: $inc" ;; esac
  done < <(grep -hE '^[[:space:]]*!include' /etc/dovecot/conf.d/10-auth.conf 2>/dev/null)
  if [[ -f /etc/pam.d/dovecot ]]; then
    while IFS= read -r v; do
      [[ $v =~ ^@include[[:space:]]+common-(auth|account|session|password)$ ]] || warn "/etc/pam.d/dovecot: $v"
    done < <(grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/dovecot)
  fi
  for f in /etc/dovecot/dovecot.conf /etc/dovecot/local.conf /etc/dovecot/conf.d/*.conf /etc/dovecot/conf.d/*.ext; do
    [[ -f $f ]] || continue
    shipped="/usr/share/dovecot/${f#/etc/dovecot/}"
    if [[ -f $shipped ]]; then
      cmp -s "$f" "$shipped" || info "Changed from the shipped copy: $f   (diff $shipped $f)"
    elif owned "$f"; then
      :
    elif [[ ${f##*/} == 99-zz-ccdc.conf ]]; then
      info "Ours: $f"
    else
      warn "Not from the package (read it; later files override earlier ones): $f"
    fi
  done
  if have doveadm; then info "Logged in to mail now:"; doveadm who 2>/dev/null | indent; fi
  if [[ -r $MAILLOG ]]; then
    info "Top sources of failed mail logins:"
    grep -h 'auth failed' "$MAILLOG" 2>/dev/null | grep -oE 'rip=[0-9a-f.:]+' | sort | uniq -c | sort -rn | head -n 5 | indent
  fi
}

# ----------------------------------------------------------------------------- roundcube
check_roundcube() {
  [[ -f $RC_CFG ]] || return 0
  hdr "Roundcube"
  local ver f m line pk unowned ws
  if have dpkg-query; then
    ver="$(dpkg-query -W -f='${Version}' roundcube-core 2>/dev/null)"
    info "roundcube-core ${ver:-not from apt}"
    if [[ -n $ver ]]; then
      if dpkg --compare-versions "$ver" ge 1.6.11 ||
         { dpkg --compare-versions "$ver" ge 1.5.10 && dpkg --compare-versions "$ver" lt 1.6; } ||
         zgrep -qs 'CVE-2025-49113' /usr/share/doc/roundcube-core/changelog.Debian.gz; then
        ok "Has the CVE-2025-49113 fix (post-login code execution)"
      else
        bad "Missing the CVE-2025-49113 fix: any logged-in user may run code as $WEBUSER. Patch, or watch webmail logins closely"
      fi
      dpkg --compare-versions "$ver" lt 1.6.20 && warn "Older than upstream 1.6.20 (Oct 2026): later security fixes may be missing"
    fi
  fi
  if grep -qF 'rcmail-!24ByteDESkey*Str' "$RC_CFG"; then bad "des_key is the public default (session passwords can be decrypted)"; else ok "des_key is not the default"; fi
  for f in "$RC_CFG" /etc/roundcube/debian-db.php; do
    [[ -f $f ]] || continue
    m="$(stat -c '%a %U:%G' "$f")"
    if [[ ${m%% *} =~ [4-7]$ ]]; then bad "$f is world-readable ($m)"; else info "$f $m"; fi
  done
  grep -qE "^[[:space:]]*\\\$config\['log_logins'\][[:space:]]*=[[:space:]]*true" "$RC_CFG" || warn "log_logins is off (no record of who logs in to webmail)"
  info "$(grep -hE "^[[:space:]]*\\\$config\['plugins'\]" "$RC_CFG" | head -n1)"
  if have dpkg; then
    verify_report < <(dpkg --verify roundcube-core 2>/dev/null)
    pk="$(dpkg-query -W -f='${Package} ${db:Status-Status}\n' 'roundcube*' 2>/dev/null | awk '$2=="installed"{print $1}')"
    if [[ -n $pk ]]; then
      # shellcheck disable=SC2086
      unowned="$(comm -13 <(dpkg -L $pk 2>/dev/null | sort -u) \
                  <(find /usr/share/roundcube /var/lib/roundcube \( -path /var/lib/roundcube/temp -o -path /var/lib/roundcube/logs \) -prune -o -type f -print 2>/dev/null | sort -u))"
      [[ -n $unowned ]] && while IFS= read -r f; do bad "File no package installed (web shell?): $f"; done <<<"$unowned"
    fi
  fi
  ws="$(grep -rlIE --include='*.php*' --include='*.phtml' "$WEBSHELL_RE" /var/www /usr/share/roundcube /var/lib/roundcube /usr/share/roundcubemail 2>/dev/null)"
  [[ -n $ws ]] && while IFS= read -r f; do bad "Web-shell pattern in $f"; done <<<"$ws"
  while IFS= read -r f; do warn "PHP file changed in the last 3 hours: $f"; done < <(find /var/www /usr/share/roundcube /var/lib/roundcube /usr/share/roundcubemail -name '*.php' -cmin -180 2>/dev/null | head -n 20)
  while IFS= read -r f; do owned "$f" || bad ".htaccess no package installed: $f"; done < <(find /var/www /usr/share/roundcube /var/lib/roundcube -name '.htaccess' 2>/dev/null)
  if [[ -r $RC_LOGDIR/errors.log ]]; then info "Recent failed webmail logins:"; grep -i 'login failed' "$RC_LOGDIR/errors.log" | tail -n 5 | cut -c1-200 | indent; fi
  if [[ -r $RC_LOGDIR/userlogins.log ]]; then info "Recent webmail logins:"; tail -n 5 "$RC_LOGDIR/userlogins.log" | indent; fi
}

# ----------------------------------------------------------------------------- apache / php / db
check_web() {
  have apache2ctl || return 0
  hdr "Apache and PHP"
  local f sec=/etc/apache2/conf-enabled/security.conf
  if systemctl is-active apache2 >/dev/null 2>&1 || pgrep -x apache2 >/dev/null; then ok "apache2 is running"; else bad "apache2 is NOT running"; fi
  [[ -f $sec ]] && grep -qE '^[[:space:]]*ServerTokens[[:space:]]+(OS|Full|Major|Minor|Min)' "$sec" && warn "ServerTokens reveals the OS and version"
  [[ -f $sec ]] && grep -qE '^[[:space:]]*ServerSignature[[:space:]]+On' "$sec" && warn "ServerSignature On (version on error pages)"
  info "Enabled sites, confs and modules:"
  find /etc/apache2/sites-enabled /etc/apache2/conf-enabled -maxdepth 1 -mindepth 1 -printf '%f -> %l\n' 2>/dev/null | sort | indent
  for f in /etc/apache2/sites-available/* /etc/apache2/conf-available/* /etc/apache2/mods-available/*; do
    [[ -f $f ]] || continue
    owned "$f" || owned "$(readlink -f "$f")" || warn "Custom Apache config (read it): $f"
  done
  grep -rnE '^[[:space:]]*(Alias|ScriptAlias|AddHandler|SetHandler|php_admin_value|php_value)' /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null | head -n 20 | indent
  if grep -qsE '^[[:space:]]*expose_php[[:space:]]*=[[:space:]]*On' /etc/php/*/apache2/php.ini &&
     ! grep -qsE 'expose_php[[:space:]]*=[[:space:]]*Off' /etc/php/*/apache2/conf.d/*.ini; then
    warn "PHP announces its version (expose_php = On)"
  fi
}

db_cli() { command -v mariadb || command -v mysql; }
check_db() {
  local cli l u h
  cli="$(db_cli)" || return 0
  pgrep -x mariadbd >/dev/null || pgrep -x mysqld >/dev/null || return 0
  hdr "MariaDB"
  while read -r _ h l _; do
    [[ $l == 3306 ]] || continue
    if is_loopback "$h"; then ok "3306 only on $h"; else bad "MariaDB listens on $h:3306 (reachable from the network)"; fi
  done < <(listeners)
  while IFS= read -r l; do
    u="${l%@*}"; h="${l##*@}"
    [[ -z $u ]] && bad "Anonymous database user @$h"
    [[ $h == % ]] && bad "Database user $u@% can connect from anywhere"
  done < <("$cli" -N -B -e "SELECT CONCAT(user,'@',host) FROM mysql.user" 2>/dev/null)
  while IFS= read -r l; do
    u="${l%@*}"
    case "$u" in root|mysql|debian-sys-maint|mariadb.sys) ;; *) warn "Database superuser: $l" ;; esac
  done < <("$cli" -N -B -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Super_priv='Y'" 2>/dev/null)
}

check_firewall() {
  hdr "Firewall"
  local s r
  if systemctl is-active firewalld >/dev/null 2>&1; then info "firewalld is active:"; firewall-cmd --list-all 2>/dev/null | indent; return 0; fi
  if have ufw; then
    s="$(ufw status verbose 2>/dev/null)"
    if [[ $s == *"Status: active"* ]]; then ok "ufw is active"; else warn "ufw is inactive: nothing is filtered"; fi
    printf '%s\n' "$s" | indent
    for r in before.rules after.rules before6.rules after6.rules; do
      [[ -f /etc/ufw/$r && -f /usr/share/ufw/iptables/$r ]] || continue
      if ! diff -q "/usr/share/ufw/iptables/$r" "/etc/ufw/$r" >/dev/null 2>&1; then
        warn "/etc/ufw/$r differs from the shipped copy (raw rules that 'ufw status' never shows):"
        diff "/usr/share/ufw/iptables/$r" "/etc/ufw/$r" | grep '^[<>]' | head -n 15 | indent
      fi
    done
    grep -q '^IPV6=no' /etc/default/ufw 2>/dev/null && warn "ufw IPV6=no: IPv6 traffic is not filtered"
  else
    warn "No ufw or firewalld found"
  fi
}

check_apparmor() {
  have aa-status || return 0
  hdr "AppArmor"
  if systemctl is-active apparmor >/dev/null 2>&1; then ok "apparmor service is active"; else warn "apparmor service is not active"; fi
  aa-status 2>/dev/null | grep -E 'profiles are (loaded|in enforce mode|in complain mode)|processes are' | indent
  local f
  for f in /etc/apparmor.d/disable/*; do [[ -e $f ]] && info "disabled profile: ${f##*/}"; done
}

# ----------------------------------------------------------------------------- baseline / diff
snapshot() {
  local d="$1" u h f
  mkdir -p "$d" && chmod 700 "$d"
  listeners | awk '{print $1, $2":"$3, $4}' > "$d/listening.txt"
  cut -d: -f1,3,4,6,7 /etc/passwd > "$d/passwd.txt"
  while IFS=: read -r u h _; do printf '%s %s\n' "$u" "$(printf '%s' "$h" | sha256sum | cut -c1-16)"; done < /etc/shadow > "$d/password-hashes.txt"
  getent group > "$d/groups.txt"
  grep -hvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/* > "$d/sudoers.txt" 2>/dev/null
  while IFS=: read -r u _ _ _ _ h _; do
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [[ -s $f ]] && ssh-keygen -lf "$f" 2>/dev/null | sed "s|^|$u |"
    done
  done < /etc/passwd | sort -u > "$d/ssh-keys.txt"
  while IFS=: read -r u _; do
    crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sed "s|^|$u: |"
  done < /etc/passwd > "$d/crontabs.txt"
  find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/crontab /etc/systemd/system \
       /etc/update-motd.d /etc/apt/apt.conf.d /etc/profile.d /etc/sudoers.d /etc/pam.d /etc/ssh /etc/postfix /etc/dovecot \
       /etc/roundcube /etc/apache2 /etc/php /etc/mysql /etc/ufw /etc/aliases /etc/rc.local /etc/ld.so.preload \
       /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile -type f -exec sha256sum {} + 2>/dev/null |
       awk '{print $2, substr($1,1,16)}' | sort > "$d/file-hashes.txt"
  systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort > "$d/enabled-units.txt"
  systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{print $(NF-1), $NF}' | sort -u > "$d/timers.txt"
  if have postconf; then postconf -n > "$d/postconf.txt" 2>/dev/null; postconf -M > "$d/postfix-master.txt" 2>/dev/null; fi
  have doveconf && doveconf -n 2>/dev/null | grep -v '^# OS:' > "$d/doveconf.txt"
  have ufw && ufw status verbose > "$d/ufw.txt" 2>/dev/null
  find /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/apache2/mods-enabled -maxdepth 1 -mindepth 1 -printf '%p -> %l\n' 2>/dev/null | sort > "$d/apache-enabled.txt"
  find / /home /var /tmp -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort -u > "$d/suid-files.txt"
}

do_baseline() {
  local d="$OUTDIR/baseline-$TS"
  snapshot "$d"
  ln -sfn "$d" "$OUTDIR/baseline-latest"
  ok "Baseline saved to $d"
  info "Later: sudo bash $SELF diff"
}

do_diff() {
  local base="$OUTDIR/baseline-latest" now="$OUTDIR/now-$TS" f n l changed=0
  [[ -d $base ]] || { bad "No baseline yet. Run: sudo bash $SELF baseline"; return 0; }
  snapshot "$now"
  hdr "Changes since $(readlink -f "$base")"
  info "Red + lines are new since the baseline; green - lines are gone."
  for f in "$base"/*.txt; do
    n="$now/${f##*/}"
    [[ -f $n ]] || continue
    diff -q "$f" "$n" >/dev/null 2>&1 && continue
    changed=1
    warn "${f##*/} changed:"
    while IFS= read -r l; do
      case "$l" in
        +*) printf '%s       + %s%s\n' "$C_R" "${l:1}" "$C_N" ;;
        -*) printf '%s       - %s%s\n' "$C_G" "${l:1}" "$C_N" ;;
      esac
    done < <(diff -u "$f" "$n" | tail -n +3 | grep -E '^[+-]')
  done
  (( changed )) || ok "Nothing changed since the baseline"
}

# ----------------------------------------------------------------------------- watch / kill
save_evidence() {
  local pid="$1" e="$OUTDIR/evidence-$TS-$1"
  mkdir -p "$e" && chmod 700 "$e"
  cmdline_of "$pid" > "$e/cmdline"
  readlink "/proc/$pid/exe" > "$e/exe-path" 2>/dev/null
  cp "/proc/$pid/exe" "$e/exe.bin" 2>/dev/null && sha256sum "$e/exe.bin" > "$e/exe.sha256"
  ls -l "/proc/$pid/fd" > "$e/open-files" 2>/dev/null
  tr '\0' '\n' < "/proc/$pid/environ" > "$e/environ" 2>/dev/null
  ss -tunpH 2>/dev/null | grep "pid=$pid," > "$e/connections"
  ps -o pid,ppid,user,lstart,cmd -p "$pid" > "$e/ps" 2>/dev/null
  cp "/proc/$pid/status" "$e/status" 2>/dev/null
  info "Evidence saved in $e"
}

kill_check() {   # kill -9, then confirm it is really gone (a zombie counts as gone)
  local pid="$1" st
  kill -9 "$pid" 2>/dev/null
  sleep 0.5
  st="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')"
  if [[ -z $st || $st == Z* ]]; then ok "Killed $pid"; else bad "PID $pid is still running (state $st)"; fi
}

do_kill() {
  [[ $# -gt 0 ]] || { echo "Usage: sudo bash $SELF kill PID [PID...]"; return 0; }
  local pid
  for pid in "$@"; do
    [[ $pid =~ ^[0-9]+$ && -d /proc/$pid ]] || { warn "No such PID: $pid"; continue; }
    [[ $pid == 1 || $pid == "$$" ]] && { bad "Refusing to kill PID $pid"; continue; }
    info "PID $pid ($(user_of "$pid")): $(cmdline_of "$pid")"
    save_evidence "$pid"
    kill_check "$pid"
  done
  warn "Killing it doesn't remove what started it: run hunt and read the Persistence section."
}

do_watch() {
  local -A seen=()
  local base_listen line out
  base_listen="$(listeners)"
  info "Watching every ${WATCH_SEC}s for reverse shells and new listeners. Ctrl-C to stop."
  info "To act on a PID: sudo bash $SELF kill PID"
  while true; do
    out="$( { net_findings; proc_findings; } 2>/dev/null )"
    while IFS= read -r line; do
      [[ -z $line || $line == *"Unexpected "* ]] && continue
      [[ -n ${seen[$line]:-} ]] && continue
      seen[$line]=1
      printf '%s %s\n' "$(date +%T)" "$line"
    done <<<"$out"
    while IFS= read -r line; do
      [[ -z $line ]] && continue
      grep -qxF -- "$line" <<<"$base_listen" && continue
      [[ -n ${seen["L $line"]:-} ]] && continue
      seen["L $line"]=1
      printf '%s %s[!!] NEW listener: %s%s\n' "$(date +%T)" "$C_R" "$line" "$C_N"
    done < <(listeners)
    sleep "$WATCH_SEC"
  done
}

# ----------------------------------------------------------------------------- harden
backup_all() {
  hdr "Backup"
  local f="$OUTDIR/backup-$TS.tgz" p db
  local -a paths=()
  for p in /etc/postfix /etc/dovecot /etc/roundcube /etc/roundcubemail /etc/apache2 /etc/php /etc/mysql /etc/aliases \
           /etc/mailname /etc/pam.d /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/ssh \
           /etc/ufw /etc/default/ufw /etc/crontab /etc/cron.d /var/spool/cron /etc/systemd/system; do
    [[ -e $p ]] && paths+=("$p")
  done
  if tar czf "$f" "${paths[@]}" 2>/dev/null; then chmod 600 "$f"; ok "Config backup: $f"; else warn "tar reported problems; check $f"; fi
  db="$(command -v mariadb-dump || command -v mysqldump)"
  if [[ -n $db ]] && pgrep -x mariadbd >/dev/null 2>&1 && "$db" --all-databases > "$OUTDIR/db-$TS.sql" 2>/dev/null; then
    chmod 600 "$OUTDIR/db-$TS.sql"; ok "Database dump: $OUTDIR/db-$TS.sql"
  else
    rm -f "$OUTDIR/db-$TS.sql"
  fi
  info "Restore one file later: tar xzf $f -C / etc/postfix/main.cf"
}

harden_accounts() {
  hdr "Harden: accounts"
  local entry u why
  local -A done_u=()
  for entry in "${SUS_USERS[@]}"; do
    u="${entry%%|*}"; why="${entry#*|}"
    [[ $u == root || -n ${done_u[$u]:-} ]] && continue
    done_u[$u]=1
    id "$u" >/dev/null 2>&1 || continue
    if [[ $u == "${SUDO_USER:-}" ]]; then warn "Skipping $u: that's the account you're using ($why)"; continue; fi
    if [[ $why == "system account with a shell" ]]; then
      if ask "Give '$u' its no-login shell back (usermod -s /usr/sbin/nologin $u)?"; then
        if usermod -s /usr/sbin/nologin "$u"; then ok "$u can no longer get a shell"; else bad "Could not change $u's shell"; fi
      fi
      continue
    fi
    if ask "Lock and expire '$u' ($why)? Undo: usermod -U -e '' $u"; then
      if usermod -L -e 1 "$u"; then ok "Locked $u"; else bad "Could not lock $u"; fi
      if [[ $(id -u "$u") != 0 ]] && pgrep -u "$u" >/dev/null && ask "Kill every process owned by $u?"; then
        pkill -KILL -u "$u" && ok "Killed $u's processes"
      fi
    fi
  done
  (( ${#done_u[@]} )) || ok "No suspicious accounts were flagged"
  if ask "Change root's password now?"; then passwd root </dev/tty; fi
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]] && ask "Change $SUDO_USER's password now?"; then passwd "$SUDO_USER" </dev/tty; fi
  info "Scored users' passwords usually change through the competition's own process."
}

harden_kill() {
  local pids pid
  pids="$(printf '%s\n' "${FLAG_PIDS[@]}" | grep -E '^[0-9]+$' | sort -un)"
  [[ -n $pids ]] || return 0
  hdr "Harden: flagged processes"
  for pid in $pids; do
    [[ -d /proc/$pid ]] || continue
    info "PID $pid  user $(user_of "$pid")  exe $(readlink "/proc/$pid/exe" 2>/dev/null)"
    info "  cmd: $(cmdline_of "$pid")"
    ss -tunpH 2>/dev/null | grep "pid=$pid," | indent
    if ask "Save evidence and kill PID $pid?"; then
      save_evidence "$pid"
      kill_check "$pid"
    fi
  done
  warn "Killing a shell doesn't remove what started it: check the Persistence section of hunt."
}

harden_postfix() {
  have postconf || return 0
  hdr "Harden: Postfix"
  local changed=0 lo='127.0.0.0/8' p v out
  cp -a /etc/postfix/main.cf "$OUTDIR/main.cf.$TS"
  [[ $(postconf -h inet_protocols) =~ (all|ipv6) ]] && lo='127.0.0.0/8 [::1]/128'
  info "mynetworks now: $(postconf -h mynetworks)"
  info "smtpd_relay_restrictions now: $(postconf -h smtpd_relay_restrictions)"
  if ask "Trust only localhost and refuse relaying for everyone else (mynetworks = $lo)?"; then
    postconf -e "mynetworks = $lo" 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
    changed=1
  fi
  if ask "Hide the banner, disable VRFY, require HELO, and stop ~/.forward from running programs?"; then
    postconf -e 'smtpd_banner = $myhostname ESMTP' 'disable_vrfy_command = yes' 'smtpd_helo_required = yes' 'allow_mail_to_commands = alias'
    changed=1
  fi
  for p in always_bcc sender_bcc_maps recipient_bcc_maps content_filter smtpd_milters non_smtpd_milters relayhost; do
    v="$(postconf -nh "$p" 2>/dev/null)"
    [[ -n $v ]] || continue
    if ask "Remove $p = $v ?"; then postconf -X "$p"; changed=1; fi
  done
  if (( changed )); then
    if out="$(postfix check 2>&1)"; then
      [[ -n $out ]] && printf '%s\n' "$out" | indent
      if postfix reload >/dev/null 2>&1; then ok "Postfix reloaded"; else warn "postfix reload failed; try: systemctl restart postfix"; fi
    else
      bad "postfix check failed, restoring main.cf:"; printf '%s\n' "$out" | indent
      cp -a "$OUTDIR/main.cf.$TS" /etc/postfix/main.cf; postfix reload >/dev/null 2>&1
    fi
  else
    info "No Postfix changes made."
  fi
  smtp_selftest
}

harden_dovecot() {
  have doveconf || return 0
  hdr "Harden: Dovecot"
  local ver f=/etc/dovecot/conf.d/99-zz-ccdc.conf low uidline="first_valid_uid = 1000" out cur wrote=0
  ver="$(dovecot --version 2>/dev/null | awk '{print $1}')"
  [[ -e $f ]] && cp -a "$f" "$OUTDIR/99-zz-ccdc.conf.$TS"
  low="$(awk -F: '$3>=100 && $3<1000 {print $1":"$6}' /etc/passwd | while IFS=: read -r u h; do
           [[ -d $h/Maildir || -s /var/mail/$u ]] && printf '%s ' "$u"; done)"
  if [[ -n $low ]]; then warn "Accounts under uid 1000 have mail ($low); leaving first_valid_uid alone"; uidline=""; fi
  if ask "Stop password logging, log why logins fail, hide the version banner${uidline:+, and block mail logins below uid 1000}?"; then
    {
      echo "# added by ccdc-mail.sh $TS (loads after the other conf.d files)"
      echo "auth_verbose = yes"
      echo "auth_verbose_passwords = no"
      [[ $ver == 2.3* ]] && echo "auth_debug_passwords = no"
      [[ -n $uidline ]] && echo "$uidline"
      echo "login_greeting = Mail server ready."
    } > "$f"
    wrote=1
  fi
  if [[ $ver == 2.4* ]]; then cur="auth_allow_cleartext = $(doveconf -h auth_allow_cleartext 2>/dev/null)"
  else cur="disable_plaintext_auth = $(doveconf -h disable_plaintext_auth 2>/dev/null)"; fi
  info "Now: ssl = $(doveconf -h ssl 2>/dev/null), $cur"
  warn "Requiring TLS breaks a scorer that logs in to IMAP/POP3 in plain text. Say yes only if you know it uses TLS."
  if ask "Require TLS for every mail login (ssl = required, no plaintext passwords)?"; then
    {
      echo "ssl = required"
      if [[ $ver == 2.4* ]]; then echo "auth_allow_cleartext = no"; else echo "disable_plaintext_auth = yes"; fi
    } >> "$f"
    wrote=1
  fi
  (( wrote )) || { info "No Dovecot changes made."; return 0; }
  if out="$(doveconf -n 2>&1 >/dev/null)"; then
    if systemctl reload dovecot 2>/dev/null || doveadm reload 2>/dev/null; then ok "Dovecot reloaded with $f"; else warn "Reload Dovecot yourself: systemctl reload dovecot"; fi
  else
    bad "doveconf rejected the change, undoing it:"; printf '%s\n' "$out" | indent
    rm -f "$f"; [[ -e $OUTDIR/99-zz-ccdc.conf.$TS ]] && cp -a "$OUTDIR/99-zz-ccdc.conf.$TS" "$f"
  fi
}

harden_roundcube() {
  [[ -f $RC_CFG ]] || return 0
  hdr "Harden: Roundcube"
  local changed=0 key block tmp f m
  local -a add=()
  cp -a "$RC_CFG" "$OUTDIR/config.inc.php.$TS"
  if grep -qF 'rcmail-!24ByteDESkey*Str' "$RC_CFG" && ask "des_key is the public default. Replace it with a random key? (logs everyone out once)"; then
    key="$(openssl rand -base64 18 | tr -d '\n')"
    sed -i -E "s|^([[:space:]]*\\\$config\['des_key'\][[:space:]]*=[[:space:]]*).*|\1'${key}';|" "$RC_CFG"
    changed=1
  fi
  grep -qE "^[[:space:]]*\\\$config\['log_logins'\][[:space:]]*=[[:space:]]*true" "$RC_CFG" || add+=("\$config['log_logins'] = true;")
  grep -qE "^[[:space:]]*\\\$config\['display_product_info'\][[:space:]]*=[[:space:]]*0" "$RC_CFG" || add+=("\$config['display_product_info'] = 0;")
  if (( ${#add[@]} )) && ! ask "Log every webmail login and hide the Roundcube version on the login page?"; then add=(); fi
  if ! grep -qE "^[[:space:]]*\\\$config\['identities_level'\][[:space:]]*=[[:space:]]*[34]" "$RC_CFG" &&
     ask "Stop webmail users from changing their From address (identities_level = 3)?"; then
    add+=("\$config['identities_level'] = 3;")
  fi
  if (( ${#add[@]} )); then
    block="$(printf '%s\n' "// added by ccdc-mail.sh $TS" "${add[@]}")"
    if grep -qE '^[[:space:]]*\?>[[:space:]]*$' "$RC_CFG"; then
      tmp="$(mktemp)"
      BLK="$block" awk '/^[[:space:]]*\?>[[:space:]]*$/ && !done {print ENVIRON["BLK"]; done=1} {print}' "$RC_CFG" > "$tmp" && cat "$tmp" > "$RC_CFG"
      rm -f "$tmp"
    else
      printf '\n%s\n' "$block" >> "$RC_CFG"
    fi
    changed=1
  fi
  for f in "$RC_CFG" /etc/roundcube/debian-db.php; do
    [[ -f $f ]] || continue
    m="$(stat -c %a "$f")"
    if [[ $m =~ [4-7]$ ]] && ask "$f is world-readable ($m). Make it 640 root:$WEBUSER?"; then
      chown "root:$WEBUSER" "$f" && chmod 640 "$f" && ok "Fixed $f"
    fi
  done
  (( changed )) || { info "No Roundcube config changes made."; return 0; }
  if have php; then
    if php -l "$RC_CFG" >/dev/null 2>&1; then ok "Roundcube config updated and passes php -l (no restart needed)"
    else bad "PHP syntax check failed, restoring the old config"; cp -a "$OUTDIR/config.inc.php.$TS" "$RC_CFG"; fi
  else
    warn "php CLI not installed, so the config wasn't syntax-checked. Load the login page now."
  fi
}

harden_web() {
  [[ -d /etc/apache2 ]] || return 0
  hdr "Harden: Apache and PHP"
  local sec=/etc/apache2/conf-available/security.conf changed=0 d
  local -a dirs=()
  if [[ -f $sec ]] && grep -qE '^[[:space:]]*(ServerTokens[[:space:]]+(OS|Full|Major|Minor|Min)|ServerSignature[[:space:]]+On)' "$sec" &&
     ask "Hide Apache and OS versions (ServerTokens Prod, ServerSignature Off)?"; then
    cp -a "$sec" "$OUTDIR/security.conf.$TS"
    sed -i -E 's/^[[:space:]]*ServerTokens[[:space:]]+.*/ServerTokens Prod/; s/^[[:space:]]*ServerSignature[[:space:]]+.*/ServerSignature Off/' "$sec"
    changed=1
  fi
  for d in /etc/php/*/apache2/conf.d /etc/php/*/fpm/conf.d; do [[ -d $d ]] && dirs+=("$d"); done
  if (( ${#dirs[@]} )) && ask "Hide the PHP version and error details (expose_php and display_errors Off)?"; then
    for d in "${dirs[@]}"; do printf 'expose_php = Off\ndisplay_errors = Off\nallow_url_include = Off\n' > "$d/99-ccdc.ini"; done
    changed=1
  fi
  (( changed )) || { info "No Apache/PHP changes made."; return 0; }
  if apache2ctl configtest >/dev/null 2>&1; then
    if systemctl reload apache2 2>/dev/null; then ok "Apache reloaded"; else warn "Reload Apache yourself: systemctl reload apache2"; fi
    for d in /etc/php/*/fpm; do [[ -d $d ]] && systemctl reload "php$(basename "$(dirname "$d")")-fpm" 2>/dev/null; done
  else
    bad "apache2ctl configtest failed, restoring:"; apache2ctl configtest 2>&1 | indent
    [[ -f $OUTDIR/security.conf.$TS ]] && cp -a "$OUTDIR/security.conf.$TS" "$sec"
  fi
}

harden_ssh() {
  have sshd || return 0
  [[ -d /etc/ssh/sshd_config.d ]] || return 0
  hdr "Harden: SSH"
  local f=/etc/ssh/sshd_config.d/00-ccdc.conf out
  local -a lines=()
  grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config || { warn "sshd_config doesn't include sshd_config.d; skipping"; return 0; }
  ask "Refuse empty passwords and limit attempts per connection (PermitEmptyPasswords no, MaxAuthTries 4)?" && lines+=("PermitEmptyPasswords no" "MaxAuthTries 4")
  warn "Blocking root over SSH breaks anything (a scorer included) that logs in as root."
  ask "Block direct root login over SSH (PermitRootLogin no)?" && lines+=("PermitRootLogin no")
  (( ${#lines[@]} )) || { info "No SSH changes made."; return 0; }
  [[ -e $f ]] && cp -a "$f" "$OUTDIR/00-ccdc.conf.$TS"
  printf '%s\n' "# added by ccdc-mail.sh $TS (00- so it wins: sshd keeps the first value it reads)" "${lines[@]}" > "$f"
  [[ -d /run/sshd ]] || mkdir -m 0755 /run/sshd    # missing until the first SSH login on 24.04
  if out="$(sshd -t 2>&1)"; then
    if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
      ok "sshd reloaded; open sessions stay up. Test a NEW login before you log out."
    else
      warn "Config is valid but the reload failed: systemctl restart ssh (open sessions stay up)"
    fi
  else
    bad "sshd -t failed, removing $f: $out"; rm -f "$f"
  fi
}

harden_firewall() {
  have ufw || return 0
  hdr "Harden: firewall (ufw)"
  if systemctl is-active firewalld >/dev/null 2>&1; then info "firewalld is active; use firewall-cmd instead of ufw."; return 0; fi
  local status proto addr port name sshp p
  local -a ports=() missing=()
  status="$(ufw status 2>/dev/null | head -n1)"
  info "$status"
  while read -r proto addr port name; do
    [[ $proto == tcp ]] || continue
    is_loopback "$addr" && continue
    [[ " $EXPECTED_TCP " == *" $port "* ]] && ports+=("$port")
  done < <(listeners)
  sshp="$(listeners | awk '$1=="tcp" && $4 ~ /^sshd?$/ {print $3; exit}')"
  ports+=("${sshp:-22}")
  mapfile -t ports < <(printf '%s\n' "${ports[@]}" | sort -un)
  info "TCP ports that would stay open: ${ports[*]}"
  warn "Everything else gets blocked, scored services included. Rerun with -p \"PORTS\" if the list is wrong."
  if [[ $status == *inactive* ]]; then
    if ask "Enable ufw (deny incoming, allow outgoing, allow ${ports[*]})?"; then
      for p in "${ports[@]}"; do ufw allow "$p/tcp" >/dev/null; done
      ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
      ufw --force enable >/dev/null && ok "ufw enabled"
      ufw status numbered | indent
    fi
  else
    for p in "${ports[@]}"; do ufw status | grep -qE "^$p/tcp[[:space:]]+ALLOW" || missing+=("$p"); done
    if (( ${#missing[@]} )) && ask "ufw is active. Add allow rules for ${missing[*]}?"; then
      for p in "${missing[@]}"; do ufw allow "$p/tcp" >/dev/null; done; ok "Rules added"
    fi
    ufw status numbered | indent
    info "Remove a rule you don't recognize: ufw delete NUMBER"
  fi
}

do_harden() {
  warn "HARDEN mode: every change asks first, and the default answer is No."
  warn "Know what the scorer checks, and look at the scoreboard after each section."
  backup_all
  snapshot "$OUTDIR/pre-harden-$TS" && info "Snapshot before changes: $OUTDIR/pre-harden-$TS"
  info "Looking for suspicious accounts and processes first (run hunt to see the full report)..."
  check_accounts >/dev/null 2>&1
  net_findings >/dev/null 2>&1
  proc_findings >/dev/null 2>&1
  RED=0; YEL=0
  harden_accounts
  harden_kill
  harden_postfix
  harden_dovecot
  harden_roundcube
  harden_web
  harden_ssh
  harden_firewall
  hdr "New baseline"
  do_baseline
  hdr "Next steps"
  info "1. Check the scoreboard now. Backups of every file changed are in $OUTDIR."
  info "2. Change scored users' passwords through the competition's process."
  info "3. Run: sudo bash $SELF hunt    then leave: sudo bash $SELF watch    running in a spare terminal."
  info "4. Run: sudo bash $SELF diff    every so often to catch changes since this baseline."
  summary "Changes were made only where you answered yes."
}

# ----------------------------------------------------------------------------- cheat sheet
cheat() {
cat <<'EOF'
=========================== CCDC MAIL BOX CHEAT SHEET (Ubuntu) ===========================
FIRST MINUTES
  sudo bash ccdc-mail.sh baseline          # snapshot before anything changes
  sudo bash ccdc-mail.sh audit | less -R   # full read-only report
  passwd                                   # your own password first; scored users via the official process
  sudo bash ccdc-mail.sh harden            # asks before every change; backups in /root/ccdc

ACCOUNTS
  awk -F: '$3==0' /etc/passwd                      # root-equivalent accounts (should be root only)
  awk -F: '$7!~/(nologin|false)$/' /etc/passwd     # accounts that can get a shell
  passwd -S -a | awk '$2=="P"'                     # accounts with a usable password
  getent group sudo; grep -r NOPASSWD /etc/sudoers /etc/sudoers.d
  find / -name 'authorized_keys*' 2>/dev/null      # then: ssh-keygen -lf FILE
  last -a | head; lastb -a | head; w              # past, failed and current logins
  usermod -L -e 1 USER                             # lock + expire   (undo: usermod -U -e '' USER)
  pkill -KILL -u USER                              # kick them off (NEVER on a uid-0 account)

REVERSE SHELLS
  ss -tnp state established                        # live connections and the process behind each
  ss -tulpn                                        # listeners and the process behind each
  ls -l /proc/PID/fd | grep socket                 # a shell with socket fds is a reverse shell
  ls -l /proc/PID/exe; tr '\0' ' ' < /proc/PID/cmdline; echo
  ps -ef --forest | less                           # who spawned it: look under apache2, cron, www-data
  kill -STOP PID                                   # freeze it while you look
  cp /proc/PID/exe /root/ccdc/evil.bin             # keeps the binary even if it was deleted
  sudo bash ccdc-mail.sh kill PID                  # evidence + kill in one step
  Then find what restarts it: crontab -l -u USER, /etc/cron.d, systemctl list-timers,
  /etc/systemd/system, ~/.bashrc, ~/.ssh/rc, /etc/update-motd.d, /etc/apt/apt.conf.d

MAIL
  postfix status; postconf -n; postconf -P; postconf -M | grep pipe
  postqueue -p | tail -1                           # queue size (spam or a loop?)
  grep -n '|' /etc/aliases; find /home /root -name '.forward*'
  sudo doveconf -n; doveadm who; doveadm kick USER-or-IP
  grep 'auth failed' /var/log/mail.log | grep -oE 'rip=[0-9.]+' | sort | uniq -c | sort -rn | head
  tail -f /var/log/mail.log /var/log/roundcube/errors.log /var/log/apache2/access.log
  Open-relay test FROM ANOTHER BOX:  nc IP 25 / EHLO x / MAIL FROM:<a@b.org> / RCPT TO:<c@gmail.com>
                                     you want 454 or 554 "Relay access denied"

FIREWALL
  ufw status numbered; ufw delete N
  ufw allow OpenSSH; ufw allow 25,143,993,443/tcp; ufw enable
  diff /usr/share/ufw/iptables/before.rules /etc/ufw/before.rules     # hidden raw rules

UNDO
  tar xzf /root/ccdc/backup-TIMESTAMP.tgz -C / etc/postfix/main.cf    # restore one file
  postfix reload; systemctl reload dovecot apache2
==========================================================================================
EOF
}

usage() {
cat <<EOF
ccdc-mail.sh $VERSION - CCDC helper for an Ubuntu mail server
  sudo bash $SELF [-u USERFILE] [-p "PORTS"] MODE
Modes: audit | hunt | harden | baseline | diff | watch [SEC] | kill PID... | cheat
  -u FILE   authorized usernames, one per line (everyone else is flagged)
  -p PORTS  expected public TCP ports, quoted (default: $EXPECTED_TCP)
EOF
}

# ----------------------------------------------------------------------------- main
main() {
  local opt mode u
  while getopts ":u:p:h" opt; do
    case "$opt" in
      u) [[ -r $OPTARG ]] || { echo "Can't read $OPTARG"; exit 1; }
         while IFS= read -r u; do u="${u//$'\r'/}"; u="${u//[[:space:]]/}"; [[ -n $u ]] && ALLOWED[$u]=1; done < "$OPTARG"
         HAVE_ALLOW=1 ;;
      p) EXPECTED_TCP="$OPTARG" ;;
      h) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done
  shift $((OPTIND-1))
  mode="${1:-audit}"
  [[ $# -gt 0 ]] && shift
  case "$mode" in
    cheat) cheat; exit 0 ;;
    help|-h|--help) usage; exit 0 ;;
  esac
  need_root "$mode"
  start_log "$mode"
  case "$mode" in
    audit)    sysinfo; check_accounts; check_network; check_procs; check_persistence; check_integrity
              check_postfix; check_dovecot; check_roundcube; check_web; check_db; check_firewall; check_apparmor; summary ;;
    hunt)     sysinfo; check_accounts; check_network; check_procs; check_persistence; check_integrity; summary ;;
    harden)   do_harden ;;
    baseline) do_baseline ;;
    diff)     do_diff ;;
    watch)    [[ ${1:-} =~ ^[0-9]+$ ]] && WATCH_SEC="$1"; do_watch ;;
    kill)     do_kill "$@" ;;
    *)        usage; exit 1 ;;
  esac
  sleep 0.5
}

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
