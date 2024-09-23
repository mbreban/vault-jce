# vault-jce

vault-jce is a Java Cryptography Extension (JCE) that delegates certain cryptographic operations to
a Vault server.

It implements Provider, KeyStoreSpi and SignatureSpi interfaces.

One of the main uses is to sign Android applications (apk) using a key stored in Vault.

The extension is compatible with Android's native [apksigner](https://developer.android.com/tools/apksigner) tool.

This extension requires Vault 1.15+ and its new transit API features.:
- [Sign CSR](https://developer.hashicorp.com/vault/api-docs/v1.15.x/secret/transit#sign-csr)
- [Set Certificate Chain](https://developer.hashicorp.com/vault/api-docs/v1.15.x/secret/transit#set-certificate-chain)

----

## Getting Started

### Setup Vault server

```sh
vault server --dev --dev-root-token-id="00000000-0000-0000-0000-000000000000"
vault secrets enable transit

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="00000000-0000-0000-0000-000000000000"
```

### Generate Vault keys and certificates

**With external root CA**

1. Generate root CA

```sh
mkdir pki

./scripts/root.sh pki/ca "/CN=root-common-name" ec
```

2. Create keys and certificates

```sh
./scripts/pki.sh pki/my-rsa-2048 "/CN=my-rsa-2048" rsa-2048 --ca-key pki/ca.key --ca-cert pki/ca.x509.pem
./scripts/pki.sh pki/my-rsa-3072 "/CN=my-rsa-3072" rsa-3072 --ca-key pki/ca.key --ca-cert pki/ca.x509.pem
./scripts/pki.sh pki/my-rsa-4096 "/CN=my-rsa-4096" rsa-4096 --ca-key pki/ca.key --ca-cert pki/ca.x509.pem
./scripts/pki.sh pki/my-ecdsa-p256 "/CN=my-ecdsa-p256" ecdsa-p256 --ca-key pki/ca.key --ca-cert pki/ca.x509.pem
./scripts/pki.sh pki/my-ecdsa-p384 "/CN=my-ecdsa-p384" ecdsa-p384 --ca-key pki/ca.key --ca-cert pki/ca.x509.pem
./scripts/pki.sh pki/my-ecdsa-p521 "/CN=my-ecdsa-p521" ecdsa-p521 --ca-key pki/ca.key --ca-cert pki/ca.x509.pem
```

**With CA stored in Vault**

1. Configure `pki` engine and create root CA

```sh
vault secrets enable pki

vault secrets tune -max-lease-ttl=87600h pki

mkdir pki

vault write -field=certificate pki/root/generate/internal \
     common_name="root-common-name" \
     issuer_name="root_ca" \
     ttl=87600h \
     key_type=ec >pki/ca.x509.pem

vault write pki/roles/android allow_any_name=true
```

2. Create keys and certificates

```sh
./scripts/pki.sh pki/my-rsa-2048 "/CN=my-rsa-2048" rsa-2048 --ca-name root_ca --ca-role "android"
./scripts/pki.sh pki/my-rsa-3072 "/CN=my-rsa-3072" rsa-3072 --ca-name root_ca --ca-role "android"
./scripts/pki.sh pki/my-rsa-4096 "/CN=my-rsa-4096" rsa-4096 --ca-name root_ca --ca-role "android"
./scripts/pki.sh pki/my-ecdsa-p256 "/CN=my-ecdsa-p256" ecdsa-p256 --ca-name root_ca --ca-role "android"
./scripts/pki.sh pki/my-ecdsa-p384 "/CN=my-ecdsa-p384" ecdsa-p384 --ca-name root_ca --ca-role "android"
./scripts/pki.sh pki/my-ecdsa-p521 "/CN=my-ecdsa-p521" ecdsa-p521 --ca-name root_ca --ca-role "android"
```

### Build vault-jce

```sh
make build
```

### Installation

1. Copy the wrapper script

The apksigner wrapper script has to be patched to load external librairies.

```sh
sudo cp etc/apksigner $ANDROID_HOME/build-tools/<BUILD_TOOLS_VERSION>/apksigner
```

2. Copy the vault-jce library

```sh
sudo cp lib/build/libs/lib-all.jar $ANDROIDHOME/build-tools/<BUILD_TOOLS_VERSION>/lib/vault-jce.jar
```

### Sign an application

```sh
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="00000000-0000-0000-0000-000000000000"

apksigner sign \
  --provider-class com.github.mbreban.vault.VaultProvider \
  --provider-arg "$VAULT_ADDR" \
  --ks NONE \
  --ks-pass "env:VAULT_TOKEN" \
  --ks-type VaultKeyStore \
  --ks-key-alias my-rsa-2048 \
  app.apk
```

## Docker image

### Build docker image

```sh
make package
```

### Sign an application

```sh
docker run --network=host -v $PWD:$PWD -w $PWD -e VAULT_ADDR=$VAULT_ADDR -e VAULT_TOKEN=$VAULT_TOKEN vault-jce:local apksigner sign ...
```

### Verify

```sh
apksigner verify --print-certs app.apk
Signer #1 certificate DN: CN=my-rsa-2048
Signer #1 certificate SHA-256 digest: 55d17a41323cbd4957628fbd6c15d5b0e3c9ccb29f10c2bd1b1999ac79c7a909
Signer #1 certificate SHA-1 digest: 51f9589ee622119c1d8df03e973ce6b9d3b497a2
Signer #1 certificate MD5 digest: ddaaba88641298ec862653a6ae1f0eae
```

### Troubleshooting

```sh
java -Djava.security.debug=all ...
```

## Resources

- https://source.android.com/docs/security/features/apksigning/v2
- http://androidxref.com/9.0.0_r3/xref/external/conscrypt/common/src/main/java/org/conscrypt/OpenSSLSignature.java#50
