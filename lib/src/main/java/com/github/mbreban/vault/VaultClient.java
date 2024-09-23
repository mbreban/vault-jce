package com.github.mbreban.vault;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.util.Assert;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.VaultHealth;
import org.springframework.vault.support.VaultTransitKey;
import org.springframework.web.client.ResourceAccessException;

public class VaultClient implements Client {

    VaultTemplate mVaultTemplate;
    VaultTransitOperations mTransit;
    VaultEndpoint mVaultEndpoint;

    public VaultClient(String address) {
        mVaultEndpoint = VaultEndpoint.from(address);
        mVaultTemplate = new VaultTemplate(mVaultEndpoint);
        mTransit = mVaultTemplate.opsForTransit();
    }

    @Override
    public VaultStatus status() throws VaultException {
        VaultHealth health;

        try {
            health = mVaultTemplate.opsForSys().health();
        } catch (org.springframework.vault.VaultException | ResourceAccessException e) {
            throw new VaultException(e.getMessage());
        }

        return new VaultStatus.Builder()
                .setInitialized(health.isInitialized())
                .setSealed(health.isSealed())
                .setVersion(health.getVersion())
                .build();
    }

    @Override
    public VaultKey read(String keyname) {
        try {
            VaultTransitKey key = mTransit.getKey(keyname);
            if (key == null) {
                return null;
            }

            VaultKey.Builder builder = new VaultKey.Builder();
            builder.setAllowPlaintextBackup(key.allowPlaintextBackup());
            // builder.setAutoRotatePeriod();
            builder.setDeletionAllowed(key.isDeletionAllowed());
            builder.setDerived(key.isDerived());
            builder.setExportable(key.isExportable());
            // builder.setImportedKey();
            builder.setKeys(key.getKeys());
            builder.setLatestVersion(key.getLatestVersion());
            // builder.setMinAvailableVersion();
            builder.setMinDecryptionVersion(key.getMinDecryptionVersion());
            builder.setMinEncryptionVersion(key.getMinEncryptionVersion());
            builder.setName(key.getName());
            builder.setSupportsDecryption(key.supportsDecryption());
            builder.setSupportsDerivation(key.supportsDerivation());
            builder.setSupportsEncryption(key.supportsEncryption());
            builder.setSupportsSigning(key.supportsSigning());
            builder.setType(key.getType());

            builder.setClient(this);
            VaultKey vk = builder.build();

            return vk;
        } catch (VaultException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    @Override
    public List<String> list() {
        List<String> keys = mTransit.getKeys();
        return keys;
    }

    @Override
    public byte[] sign(String keyName, byte[] bytes, String hashAlgorithm, String signatureAlgorithm, boolean prehashed, String saltLength) {
        Assert.hasText(keyName, "Key name must not be empty");

        // Map<String, Object> request = toRequestBody(bytes, hashAlgorithm, signatureAlgorithm, prehashed, saltLength);
        Map<String, Object> request = new RequestBuilder()
                .setInput(bytes)
                .setHashAlgorithm(hashAlgorithm)
                .setSignatureAlgorithm(signatureAlgorithm)
                .setPrehashed(prehashed)
                .setSaltLength(saltLength)
                .build();

        String signature = (String) mVaultTemplate.write("transit/sign/%s".formatted(keyName), request)
                .getRequiredData()
                .get("signature");

        final String b64Signature = signature.split(":")[2];
        final byte[] raw = Base64.getDecoder().decode(b64Signature);

        return raw;
    }

    @Override
    public boolean verify(String keyName, byte[] plaintext, String hashAlgorithm,
            String signatureAlgorithm, boolean prehashed, byte[] signature) {
        Assert.hasText(keyName, "Key name must not be empty");

        Map<String, Object> request = new RequestBuilder()
                .setInput(plaintext)
                .setSignature(signature)
                .setHashAlgorithm(hashAlgorithm)
                .setPrehashed(prehashed)
                .setSignatureAlgorithm(signatureAlgorithm)
                .build();

        Boolean valid = (Boolean) mVaultTemplate.write("transit/verify/%s".formatted(keyName), request)
                .getRequiredData()
                .get("valid");

        return valid;
    }

    @Override
    public void authenticate(String token) {
        ClientAuthentication clientAuthentication = new TokenAuthentication(token);

        mVaultTemplate = new VaultTemplate(mVaultEndpoint, clientAuthentication);
        mTransit = mVaultTemplate.opsForTransit();
    }

    public static class RequestBuilder {

        String input;
        String signature;
        String hashAlgorithm;
        Boolean prehashed;
        String signatureAlgorithm;
        String saltLength;

        public RequestBuilder setInput(byte[] input) {
            String encoded = Base64.getEncoder().encodeToString(input);
            this.input = encoded;
            return this;
        }

        public RequestBuilder setSignature(byte[] signature) {
            String encoded = Base64.getEncoder().encodeToString(signature);
            this.signature = "vault:v1:" + encoded;
            return this;
        }

        public RequestBuilder setHashAlgorithm(String hashAlgorithm) {
            this.hashAlgorithm = hashAlgorithm;
            return this;
        }

        public RequestBuilder setPrehashed(Boolean prehashed) {
            this.prehashed = prehashed;
            return this;
        }

        public RequestBuilder setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        public RequestBuilder setSaltLength(String saltLength) {
            this.saltLength = saltLength;
            return this;
        }

        public Map<String, Object> build() {
            Map<String, Object> request = new LinkedHashMap<>();

            request.put("prehashed", prehashed);
            if (hashAlgorithm != null && !hashAlgorithm.isEmpty()) {
                request.put("hash_algorithm", hashAlgorithm);
            }
            if (input != null && !input.isEmpty()) {
                request.put("input", input);
            }
            if (signature != null && !signature.isEmpty()) {
                request.put("signature", signature);
            }
            if (signatureAlgorithm != null && !signatureAlgorithm.isEmpty()) {
                request.put("signature_algorithm", signatureAlgorithm);
            }
            if (saltLength != null && !saltLength.isEmpty()) {
                request.put("salt_length", saltLength);
            }

            return request;
        }
    }
}
