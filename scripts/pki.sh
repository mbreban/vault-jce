#!/usr/bin/env bash

set -e

function clean_tmpdir() {
    rm -rf ${tmpdir}
}

function usage() {
    cat <<EOF
Usage: $0 <name> <subject> <keytype> [OPTIONS...]

Decrypt encrypted <FILE> with given nonce and shares. Then, encrypt the secret
again for a new list of recipients. Resulting artifacts are stored in <DIR>.

Options:
    -h|--help                       show this help
    --ca-key                        CA key file
    --ca-cert                       CA certificate file
    --ca-name                       Vault CA key name
    --ca-role                       Vault pki role name
    -a | --vault-addr               Vault address
    -t | --vault-token              Vault token
    -o|--out <file>                 output file for encrypted secret

EOF
    exit 0
}

tmpdir=$(mktemp -d)
trap 'clean_tmpdir' EXIT INT QUIT

POSITIONAL=()
OPTS=()
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
    --ca-key)
        ca_key="$2"
        shift 2 || usage
        ;;
    --ca-cert)
        ca_cert="$2"
        shift 2 || usage
        ;;
    --ca-name)
        ca_name="$2"
        shift 2 || usage
        ;;
    --ca-role)
        ca_role="$2"
        shift 2 || usage
        ;;
    -a | --vault-addr)
        export VAULT_ADDR="$2"
        shift 2 || usage
        ;;
    -t | --vault-token)
        export VAULT_TOKEN="$2"
        shift 2 || usage
        ;;
    *)
        POSITIONAL+=("$1")
        shift
        ;;
    esac
done

set -- "${POSITIONAL[@]}"

if [ "$#" -ne 3 ]; then
    usage
fi

if [[ -e $1.x509.pem ]]; then
    echo "$1.x509.pem already exists; please delete it first" >&2
    echo "if you want to replace it." >&2
    exit 1
fi

name="$1"
key_name="$(basename $1)"
subject="$2"
key_type="$3"

case $key_type in
rsa-2048 | rsa-3072 | rsa-4096 | ecdsa-p256 | ecdsa-p384 | ecdsa-p521) ;;
*)
    echo "invalid key type" >&2
    ;;
esac

if [[ -n "${ca_key}" && -n "${ca_name}" ]]; then
    echo "--ca-key and --ca-name are mutually exclusive" >&2
    exit 1
fi

if [[ -n "${ca_key}" && -z "${ca_cert}" ]]; then
    echo "--ca-cert is not defined" >&2
    exit 1
fi

if [[ -n "${ca_name}" && -z "${ca_role}" ]]; then
    echo "--ca-role is not defined" >&2
    exit 1
fi

if [ -z "${VAULT_ADDR}" ]; then
    echo "VAULT_ADDR is not set" >&2
    exit 1
fi

if [ -z "${VAULT_TOKEN}" ]; then
    echo "VAULT_TOKEN is not set" >&2
    exit 1
fi

cat <<EOF >${tmpdir}/csr.cnf
[ req ]
# default_bits       = 2048
# prompt             = no
# default_md         = sha256
# distinguished_name = dn
req_extensions     = req_ext

[ req_ext ]
# basicConstraints = CA:TRUE
keyUsage = digitalSignature
# critical, keyCertSign, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = codeSigning
# serverAuth, clientAuth, emailProtection, timeStamping
# nsCertType = client, server, email, objsign, sslCA, emailCA, objCA
# subjectAltName = @alt_names
# subjectKeyIdentifier = hash
EOF

openssl ecparam -name prime256v1 -genkey -noout >${tmpdir}/tmp.key
openssl req -new -nodes -key ${tmpdir}/tmp.key -out ${tmpdir}/template.csr -subj "${subject}" -config ${tmpdir}/csr.cnf

echo "Creating ${key_name} (${key_type})..."
vault write -f transit/keys/${key_name} type=${key_type} >/dev/null

echo "Creating ${key_name} CSR..."
vault write -field=csr transit/keys/${key_name}/csr csr="$(<${tmpdir}/template.csr)" >${tmpdir}/${key_name}.csr

echo "Creating ${key_name} certificate chain..."

if [[ -n "${ca_key}" ]]; then
    openssl x509 -req -days 7 -sha512 -in ${tmpdir}/${key_name}.csr -CA ${ca_cert} -CAkey ${ca_key} -CAcreateserial -out ${name}.x509.pem
    cat ${name}.x509.pem ${ca_cert} >${tmpdir}/chain.pem
elif [[ -n "${ca_name}" ]]; then
    vault write -format=json pki/sign/${ca_role} \
        issuer_ref="${ca_name}" \
        csr=@${tmpdir}/${key_name}.csr \
        format=pem_bundle ttl="43800h" |
        jq -r '.data.certificate' >${tmpdir}/chain.pem
fi

vault write transit/keys/${key_name}/set-certificate certificate_chain="$(<${tmpdir}/chain.pem)" >/dev/null

# openssl x509 -noout -text -in app.x509.pem
