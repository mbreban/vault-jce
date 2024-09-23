package com.github.mbreban.vault;

import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;

import com.fasterxml.jackson.databind.ObjectMapper;

public final class VaultKey implements PrivateKey, PublicKey, Signer, Verifier {

    Client client;
    SubjectPublicKeyInfo latestPublicKeyInfo;

    // Vault REST API
    boolean allowPlaintextBackup;
    int autoRotatePeriod;
    boolean deletionAllowed;
    boolean derived;
    boolean exportable;
    boolean importedKey;
    Map<Integer, AsymetricKeyVersion> keys;
    int latestVersion;
    int minAvailableVersion;
    int minDecryptionVersion;
    int minEncryptionVersion;
    String name;
    boolean supportsDecryption;
    boolean supportsDerivation;
    boolean supportsEncryption;
    boolean supportsSigning;
    String type;

    private VaultKey(Builder builder) throws VaultException {
        this.client = builder.client;
        this.allowPlaintextBackup = builder.allowPlaintextBackup;
        this.autoRotatePeriod = builder.autoRotatePeriod;
        this.deletionAllowed = builder.deletionAllowed;
        this.derived = builder.derived;
        this.exportable = builder.exportable;
        this.importedKey = builder.importedKey;
        this.latestVersion = builder.latestVersion;
        this.minAvailableVersion = builder.minAvailableVersion;
        this.minDecryptionVersion = builder.minDecryptionVersion;
        this.minEncryptionVersion = builder.minEncryptionVersion;
        this.name = builder.name;
        this.supportsDecryption = builder.supportsDecryption;
        this.supportsDerivation = builder.supportsDerivation;
        this.supportsEncryption = builder.supportsEncryption;
        this.supportsSigning = builder.supportsSigning;
        this.type = builder.type;

        this.keys = new HashMap<>();

        final Map<String, Object> k = builder.keys;
        ObjectMapper mapper = new ObjectMapper();

        for (Map.Entry<String, Object> entry : k.entrySet()) {
            AsymetricKeyVersion akv;
            if (this.type.startsWith("rsa") || this.type.startsWith("ec")) {
                akv = mapper.convertValue(entry.getValue(), AsymetricKeyVersion.class);
            } else {
                throw new VaultException("Key type not supported (only rsa and ecdsa)");
            }

            Integer version = Integer.valueOf(entry.getKey());
            this.keys.put(version, akv);
        }

        try {
            AsymetricKeyVersion akv = getKeyVersion(latestVersion);
            this.latestPublicKeyInfo = publicKeyFromPEM(akv.getPublicKey());
        } catch (IOException e) {
            throw new VaultException(e.getMessage());
        }
    }

    private SubjectPublicKeyInfo publicKeyFromPEM(String pem) throws IOException {
        StringReader reader = new StringReader(pem);
        try (PEMParser pemParser = new PEMParser(reader)) {
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            return subjectPublicKeyInfo;
        }
    }

    @Override
    public String getAlgorithm() {
        return this.type;
    }

    @Override
    public byte[] getEncoded() {
        try {
            return this.latestPublicKeyInfo.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String getFormat() {
        return "DER";
    }

    public boolean isAllowPlaintextBackup() {
        return allowPlaintextBackup;
    }

    public int getAutoRotatePeriod() {
        return autoRotatePeriod;
    }

    public boolean isDeletionAllowed() {
        return deletionAllowed;
    }

    public boolean isDerived() {
        return derived;
    }

    public boolean isExportable() {
        return exportable;
    }

    public boolean isImportedKey() {
        return importedKey;
    }

    public AsymetricKeyVersion getKeyVersion(int version) {
        AsymetricKeyVersion kv = this.keys.get(version);
        return kv;
    }

    public int getLatestVersion() {
        return latestVersion;
    }

    public int getMinAvailableVersion() {
        return minAvailableVersion;
    }

    public int getMinDecryptionVersion() {
        return minDecryptionVersion;
    }

    public int getMinEncryptionVersion() {
        return minEncryptionVersion;
    }

    public String getName() {
        return name;
    }

    public boolean isSupportsDecryption() {
        return supportsDecryption;
    }

    public boolean isSupportsDerivation() {
        return supportsDerivation;
    }

    public boolean isSupportsEncryption() {
        return supportsEncryption;
    }

    public boolean isSupportsSigning() {
        return supportsSigning;
    }

    public String getType() {
        return type;
    }

    static VaultKey fromPrivateKey(PrivateKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key is null");
        }
        if (key instanceof VaultKey vaultKey) {
            return vaultKey;
        }
        throw new InvalidKeyException("Invalid key type; expected VaultKey");
    }

    static VaultKey fromPublicKey(PublicKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key is null");
        }
        if (key instanceof VaultKey vaultKey) {
            return vaultKey;
        }
        throw new InvalidKeyException("Invalid key type; expected VaultKey");
    }

    @Override
    public byte[] sign(byte[] hash, String hashAlgorithm, String signatureAlgorithm, String saltLength) throws VaultException {
        if (this.client == null) {
            throw new VaultException("Client is null");
        }
        return this.client.sign(name, hash, hashAlgorithm, signatureAlgorithm, true, saltLength);
    }

    @Override
    public Boolean verify(byte[] hash, String hashAlgorithm, String signatureAlgorithm,
            byte[] signature) throws VaultException {
        if (this.client == null) {
            throw new VaultException("Client is null");
        }
        return this.client.verify(name, hash, hashAlgorithm, signatureAlgorithm, true, signature);
    }

    public static class Builder {

        Client client;

        boolean allowPlaintextBackup;
        int autoRotatePeriod;
        boolean deletionAllowed;
        boolean derived;
        boolean exportable;
        boolean importedKey;
        Map<String, Object> keys;
        int latestVersion;
        int minAvailableVersion;
        int minDecryptionVersion;
        int minEncryptionVersion;
        String name;
        boolean supportsDecryption;
        boolean supportsDerivation;
        boolean supportsEncryption;
        boolean supportsSigning;
        String type;

        public Builder setClient(Client client) {
            this.client = client;
            return this;
        }

        public Builder setAllowPlaintextBackup(boolean allowPlaintextBackup) {
            this.allowPlaintextBackup = allowPlaintextBackup;
            return this;
        }

        public Builder setAutoRotatePeriod(int autoRotatePeriod) {
            this.autoRotatePeriod = autoRotatePeriod;
            return this;
        }

        public Builder setDeletionAllowed(boolean deletionAllowed) {
            this.deletionAllowed = deletionAllowed;
            return this;
        }

        public Builder setDerived(boolean derived) {
            this.derived = derived;
            return this;
        }

        public Builder setExportable(boolean exportable) {
            this.exportable = exportable;
            return this;
        }

        public Builder setImportedKey(boolean importedKey) {
            this.importedKey = importedKey;
            return this;
        }

        public Builder setKeys(Map<String, Object> keys) {
            this.keys = keys;
            return this;
        }

        public Builder setLatestVersion(int latestVersion) {
            this.latestVersion = latestVersion;
            return this;
        }

        public Builder setMinAvailableVersion(int minAvailableVersion) {
            this.minAvailableVersion = minAvailableVersion;
            return this;
        }

        public Builder setMinDecryptionVersion(int minDecryptionVersion) {
            this.minDecryptionVersion = minDecryptionVersion;
            return this;
        }

        public Builder setMinEncryptionVersion(int minEncryptionVersion) {
            this.minEncryptionVersion = minEncryptionVersion;
            return this;
        }

        public Builder setName(String name) {
            this.name = name;
            return this;
        }

        public Builder setSupportsDecryption(boolean supportsDecryption) {
            this.supportsDecryption = supportsDecryption;
            return this;
        }

        public Builder setSupportsDerivation(boolean supportsDerivation) {
            this.supportsDerivation = supportsDerivation;
            return this;
        }

        public Builder setSupportsEncryption(boolean supportsEncryption) {
            this.supportsEncryption = supportsEncryption;
            return this;
        }

        public Builder setSupportsSigning(boolean supportsSigning) {
            this.supportsSigning = supportsSigning;
            return this;
        }

        public Builder setType(String type) {
            this.type = type;
            return this;
        }

        public VaultKey build() throws VaultException {
            return new VaultKey(this);
        }
    }
}
