#!/usr/bin/env bash

set -e

function usage() {
    cat <<EOF
Usage: $0 <name> <subject> <keytype>

Creates <name>.key key and <name>.x509.pem cert. Cert contains the
given <subject>. A keytype of "rsa" or "ec" is accepted.
EOF
    exit 0
}

if [ "$#" -ne 3 ]; then
    usage
fi

if [[ -e $1.key || -e $1.x509.pem ]]; then
    echo "$1.key and/or $1.x509.pem already exist; please delete them first" >&2
    echo "if you want to replace them." >&2
    exit 1
fi

name="$1"
subject="$2"
key_type="$3"

case $key_type in
rsa)
    openssl genrsa -f4 2048>${name}.key
    ;;
ec)
    openssl ecparam -name prime256v1 -genkey -noout >${name}.key
    ;;
*)
    echo "invalid key type" >&2
    exit 1
    ;;
esac

openssl req -x509 -new -nodes -key ${name}.key -sha512 -days 30 -subj "${subject}" -out ${name}.x509.pem
