#!/bin/bash
# -- START
# -- CHECK FOR @modify LINES IN THE SOURCE
# Exit immediately if non-zero return.
set -e

# Initialize flags
DEBUG=0
DRY_RUN=0
NOAUTO=0
UNDO=0
HELP=0
NOAUTH=0 # not an arg

# Parse command-line arguments
OPTIONS=$(getopt -o dnAuh --long debug,dry-run,no-auto,undo,help -- "$@")
eval set -- "$OPTIONS"
while true; do
    case "$1" in
        -d|--debug)     DEBUG=1; shift ;;
        -n|--dry-run)   DRY_RUN=1; shift ;;
        -A|--no-auto)   NOAUTO=1; shift ;;
        -u|--undo)      UNDO=1; shift ;;
        -h|--help)      HELP=1; shift ;;
        --)             shift; break ;;
        *)              echo "Invalid option $1" >&2; exit 1 ;;
    esac
done

if [[ $HELP -eq 1 ]]; then
    cat << EOF
Usage: autonordvpn.sh [OPTIONS]

Options:
    (NO OPTION)     FULL SETUP.
    -d, --debug     DEBUG ON (bash -x)
    -n, --dry-run   PRINT; NO EXECUTE (bash -v -n)
    -A, --no-auto   NO RUN ON BOOT
        --undo      REVERSE ALL CHANGES (incl. sudo priv)
    -h, --help      SHOW THIS HELP TEXT
Examples:
    ./autonordvpn.sh        # Default. Prompts for sudo privileges.
    ./autonordvpn.sh --undo # Undo previous ./autonordvpn.sh

EOF
    exit 0
fi

# Change cwd to makeconf path
cd "$(dirname "$0")"

# Start time
echo "START"
date +"%H:%M:%S"
echo "# hi."

# Debug mode
if [[ $DEBUG -eq 1 ]]; then
    echo "INFO: DEBUG ON"
    set -x
fi

# Dry-run mode
if [[ $DRY_RUN -eq 1 ]]; then
    echo "INFO: DRY RUN ON; NO EXECUTE"
    set -v
    set -n
fi

if [[ $UNDO -eq 1 ]]; then
    cat << EOF
INFO: UNDO ON
INFO: UNDO searches /etc/openvpn/ and $(pwd)/nvpn
EOF
    # Arrays
    declare -a F=() # Files
    declare -a S=() # Services

    # Gather files if they exist
    [[ -d ./nvpn ]] && F+=("./nvpn")
    [[ -d /etc/openvpn/conf ]] && F+=("/etc/openvpn/conf")
    [[ -d /etc/openvpn/ovpn_udp ]] && F+=("/etc/openvpn/ovpn_udp")
    [[ -f /etc/openvpn/auth.conf ]] && F+=("/etc/openvpn/auth.conf")
    [[ -f /etc/openvpn/nordvpn.conf ]] && F+=("/etc/openvpn/nordvpn.conf")

    # Gather services if they are enabled
    if systemctl is-enabled openvpn@nordvpn.service &>/dev/null; then
        S+=("openvpn@nordvpn.service")
    fi
    if systemctl is-enabled openvpn.service &>/dev/null; then
        S+=("openvpn.service")
    fi

    # Exit if none found
    if [[ ${#F[@]} -eq 0 && ${#S[@]} -eq 0 ]]; then
        echo "FOUND: NOTHING"
        date +"%H:%M:%S"
        echo "END"
        exit 0
    fi


    # Print files
    if [[ ${#F[@]} -gt 0 ]]; then
        for file in "${F[@]}"; do
            echo "FOUND: $file"
        done
    else echo "FOUND: NO FILES"
    fi

    # Print services
    if [[ ${#S[@]} -gt 0 ]]; then
        for serv in "${S[@]}"; do
            echo "FOUND: $serv"
        done
    else echo "FOUND: NO SERVICES"
    fi

    read -r -p "Remove ALL files and disable ALL services? [y/N]: " ch
    case "${ch,,}" in
        y)
            # Remove files
            if [[ "${#F[@]} -gt 0" ]]; then
                sudo rm -rf "${F[@]}"
            fi

            # Disable services
            if [[ "${#S[@]} -gt 0" ]]; then
                for serv in "${S[@]}"; do
                    sudo systemctl stop "$serv" || true
                    sudo systemctl disable "$serv" || true
                done
            fi 
            echo "INFO: UNDO OFF" ;;
        *)  echo "DID NOT REMOVE ANYTHING"; echo "EXIT"
        ;;
    esac

    date +"%H:%M:%S"
    echo "END"
    exit 0
fi


cat << EOF
INFO: Make OpenVPN conf for NordVPN
INFO: Tested on Debian 12
INFO: Read source autonordvpn.sh
INFO: Install openvpn 
INFO: Docs https://wiki.debian.org/OpenVPN
INFO: Consult /usr/share/doc/openvpn/examples/
EOF


# -- CHECK DEPENDENCIES
# OpenVPN package
if ! dpkg -s openvpn 2>/dev/null | grep -q "install ok installed"; then
    cat << EOF
WARNING: Unstable check. Used anyways:

dpkg -s openvpn 2>/dev/null | grep -q "install ok installed"
OUT: OpenVPN not installed

EOF
    read -p "Install OpenVPN? [y/N]: " ch
    if [[ "${ch,,}" == "y" ]]; then
        sudo apt update
        sudo apt install openvpn
    else
        echo "ABORT: Cannot proceed without OpenVPN"
        exit 1
    fi
fi

# System packages -- this should come preinstalled w Debian
missingdep=()
for cmd in curl awk systemctl mkdir rm cp sudo grep pushd popd unzip echo \
    touch cat; do
    if ! command -v "$cmd" &>/dev/null; then
        missingdep+=("$cmd")
    fi
done

if [[ ${#missingdep[@]} -gt 0 ]]; then
    echo "Missing dependencies: ${missingdep[*]}"
    read -p "Install? [y/N]: " ch
    if [[ "${ch,,}" == "y" ]]; then
        sudo apt update
        sudo apt install "${missingdep[@]}"
    else
        echo "ABORT: Cannot proceed without these dependencies"
        exit 1
    fi
fi

# -- FETCH SERVERS
mkdir -p nvpn/ovpn_udp
pushd nvpn > /dev/null

# Fetch full server list from NordVPN if online
if [[ $DRY_RUN -eq 0 ]]; then
    pushd ovpn_udp > /dev/null
    curl --max-time 10 -o ovpn.zip --show-error --silent \
    https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip || {
        echo "Error: Failed to fetch server list." >&2
        exit 1
    }
    unzip -q -j ovpn.zip "ovpn_udp/*" -d .
    rm ovpn.zip
    popd > /dev/null
fi

# DEFINE SERVERS -- @modify TO MATCH
MAIN="es*"
CLOSE="es* it* fr* pt*"
REGION="es* it* fr* pt* de* dk* no* se* nl*"
ALL="*"

# Create serverlists
touch main.txt close.txt region.txt all.txt

# Clutter -- BEGIN
if [[ $DEBUG -eq 1 ]]; then
    echo "DEBUG: OFF, clutter."
    set +x
fi
# Server $MAIN fetch
grep -h '^remote [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+ 1194' \
ovpn_udp/${MAIN}.nordvpn.com.udp.ovpn > main.txt

# Server $CLOSE fetch
for i in $CLOSE; do
    grep -h '^remote [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+ 1194' \
    ovpn_udp/${i}.nordvpn.com.udp.ovpn >> close.txt
done

# Server $REGION fetch
for i in $REGION; do
    grep -h '^remote [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+ 1194' \
    ovpn_udp/${i}.nordvpn.com.udp.ovpn >> region.txt
done

# Server $ALL fetch
grep -h '^remote [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+ 1194' \
ovpn_udp/${ALL}.nordvpn.com.udp.ovpn > all.txt

# Function to add duplicate lines with port 443
addport() {
    local f="$1"
    awk '{print $0; $NF="443"; print $0}' "$f" > t && mv t "$f"
}

# Apply addport to each file
addport "main.txt"
addport "close.txt"
addport "region.txt"
addport "all.txt"


# -- FETCH TLS_KEY AND CA_CERT
# @modify es* server bias
awk '/<ca>/,/<\/ca>/ { print; if (/<\/ca>/) exit }' \
ovpn_udp/es*.ovpn > ca_cert.txt
# extract the first <tls-auth> block
awk '/<tls-auth>/,/<\/tls-auth>/ { print; if (/<\/tls-auth>/) exit }' \
ovpn_udp/es*.ovpn > tls_key.txt

# -- CONF FILES
createconf() {
    local filename="$1"
    local serverlist="$2"
    CONFBASE=$(cat << EOF
client
dev tun # @modify default
proto udp # @modify default
$(cat "$serverlist")
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ping 15 # @modify
ping-restart 60 # @modify
ping-timer-rem
reneg-sec 0
comp-lzo no
remote-random # select random server from all 'remote' directives
route 192.168.0.0 255.255.255.0 net_gateway # @modify to match LAN
auth-user-pass /etc/openvpn/auth.conf # @modify make sure
verb 3 # @modify increase for debugging
remote-cert-tls server
pull
fast-io
cipher AES-256-CBC
auth SHA512
$(cat ca_cert.txt)
key-direction 1
$(cat tls_key.txt)
# -- END
EOF
)
    cat << EOF > "$filename"
# hi.
# -- START
# -- file autogen via autonordvpn.sh
$CONFBASE
EOF
}

createconf "nordvpn.conf" "main.txt"
createconf "nordvpnclose.conf" "close.txt"
createconf "nordvpnregion.conf" "region.txt"
createconf "nordvpnall.conf" "all.txt"

# Clutter -- END
if [[ $DEBUG -eq 1 ]]; then
    echo "DEBUG: ON"
    set -x
fi

if [[ ! -f /etc/openvpn/auth.conf ]]; then
    # ALERT: /etc/openvpn/auth.conf
    NOAUTH=1
    cat << EOF
ALERT: /etc/openvpn/auth.conf NOT FOUND
ALERT: Making stub file in /etc/openvpn/auth.conf
ALERT: Edit the file with your NordVPN service credentials
ALERT: https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/service-credentials/
ALERT: or systemd will faill with (see journalctl -u openvpn@nordvpn)

WARNING: cannot stat file '/etc/openvpn/auth.conf'>
         Options error: --auth-user-pass fails with '/etc/openvpn/auth.conf'>
         Options error: Please correct these errors.

TIP: Increase verb (default, verb 3) value in nordvpn.conf for debugging

EOF
    # Create auth.conf stub @modify
    # Get your service credentials from:
    # https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/service-credentials/
    cat << EOF > auth.conf
<User>      # Replace the entire line with your username. No more lines.
<Password>  # Replace the entire line with your password. No more lines.
EOF

    sudo cp auth.conf /etc/openvpn/auth.conf

else 
    cat << EOF
FOUND: /etc/openvpn/auth.conf
ALERT: Make sure it's valid. Only two lines, User and Password.
EOF

# !NOAUTO, clean, suggest and exit
if [[ $NOAUTO -eq 1 ]]; then
    cat << EOF 
INFO: NOAUTO set, prepare to exit
INFO: Copy files here /etc/openvpn/
/etc/openvpn/nordvpn.conf (mandatory, pick conf)
/etc/openvpn/auth.conf    (mandatory)
/etc/openvpn/conf/*.conf  (optional)
/etc/openvpn/ovpn_udp     (optional)
INFO: Enable systemd services to run on boot
$ systemctl enable openvpn@nordvpn.service
$ systemctl enable openvpn.service
$ systemctl start openvpn@nordvpn.service
$ systemctl start openvpn.service
INFO: Manually run OpenVPN
$ /usr/sbin/openvpn --daemon --config /etc/openvpn/nordvpn.conf
$ /usr/sbin/openvpn --daemon --config /etc/openvpn/conf/%i.conf (pick 1)
$ /usr/sbin/openvpn --daemon --config /etc/openvpn/ovpn_udp/%i.ovpn (pick 1)

EOF

    rm main.txt close.txt region.txt all.txt 2>/dev/null || true
    (popd || true) > /dev/null

    # Reset dry-run & debug for neatness
    set +v; set +n; set +x

    date +"%H:%M:%S"
    echo "END"
    exit 0
fi


# -- RUN ON BOOT
# Requires sudo privileges
if [[ -f /etc/openvpn/conf/nordvpnclose.conf || \
      -f /etc/openvpn/conf/nordvpnregion.conf   || \
      -f /etc/openvpn/conf/nordvpnall.conf  || \
      -d /etc/openvpn/ovpn_udp              || \
      -f /etc/openvpn/nordvpn.conf ]]; then

    echo "INFO: OpenVPN config found in /etc/openvpn/"
    read -p "Delete existing files and proceed [y/N]: " choice
    if [[ "${choice,,}" == "y" ]]; then
        sudo rm -r /etc/openvpn/ovpn_udp \
                   /etc/openvpn/conf \
                   /etc/openvpn/nordvpn.conf 2>/dev/null || true
        echo "INFO: Existing files deleted"
    else
        echo "INFO: Operation canceled"
        exit 1
    fi
else
    echo "INFO: No existing OpenVPN config in /etc/openvpn/"
fi


# -- SET CONFIG
# DO ALWAYS
sudo mkdir -p /etc/openvpn/conf
sudo cp nordvpn.conf -r ovpn_udp/ -t /etc/openvpn/
sudo cp nordvpnclose.conf nordvpnregion.conf nordvpnall.conf -t /etc/openvpn/conf/

    if [[ $NOAUTH -eq 1 ]]; then
        cat << EOF
INFO: No autoconfigure systemd services
INFO: Since no valid /etc/openvpn/auth.conf
INFO: First, create valid auth.conf
INFO: Then do the following

$ sudo systemctl enable openvpn@nordvpn.service
$ sudo systemctl enable openvpn.service
$ sudo systemctl start openvpn@nordvpn.service
$ sudo systemctl start openvpn.service
$ sudo systemctl daemon-reload

TIP: Quick test for VPN working
$ curl ifconfig.me ; echo "" (NordVPN IP or yours?)
$ ip addr (see tun0 interface?)

EOF
    else
        # Enable systemd units to run on boot
        sudo systemctl enable openvpn@nordvpn.service
        sudo systemctl enable openvpn.service
        sudo systemctl start openvpn@nordvpn.service
        sudo systemctl start openvpn.service
        sudo systemctl daemon-reload
    fi

# Clean cwd
rm main.txt close.txt region.txt all.txt 2>/dev/null || true

# return ../nvpn
(popd || true) > /dev/null

# Reset dry-run & debug
set +v; set +n; set +x

date +"%H:%M:%S"
echo "END"
# -- END
