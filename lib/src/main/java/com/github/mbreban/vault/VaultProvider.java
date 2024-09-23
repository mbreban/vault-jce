package com.github.mbreban.vault;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class VaultProvider extends Provider {

    public static final String PROVIDER_NAME = "VaultProvider";

    private static final String PREFIX = VaultProvider.class.getPackage().getName() + ".";

    private static final String ADDR = "http://127.0.0.1:8200";

    public VaultProvider() {
        this(ADDR);
    }

    public VaultProvider(String address) {
        this(PROVIDER_NAME, address);
    }

    @SuppressWarnings("deprecation")
    protected VaultProvider(String name, String address) {
        super(name, 1.0, "Vault-backed security provider");

        putSignatureImpl("SHA1withRSA", "VaultSignature$SHA1RSA");
        put("Alg.Alias.Signature.SHA1withRSAEncryption", "SHA1withRSA");
        put("Alg.Alias.Signature.SHA1/RSA", "SHA1withRSA");
        put("Alg.Alias.Signature.SHA-1/RSA", "SHA1withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.1", "SHA1withRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.5", "SHA1withRSA");
        put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
        put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");

        putSignatureImpl("SHA224withRSA", "VaultSignature$SHA224RSA");
        put("Alg.Alias.Signature.SHA224withRSAEncryption", "SHA224withRSA");
        put("Alg.Alias.Signature.SHA224/RSA", "SHA224withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.14", "SHA224withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.14", "SHA224withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.113549.1.1.1",
                "SHA224withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.113549.1.1.14",
                "SHA224withRSA");

        putSignatureImpl("SHA256withRSA", "VaultSignature$SHA256RSA");
        put("Alg.Alias.Signature.SHA256withRSAEncryption", "SHA256withRSA");
        put("Alg.Alias.Signature.SHA256/RSA", "SHA256withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", "SHA256withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.1",
                "SHA256withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.113549.1.1.11",
                "SHA256withRSA");

        putSignatureImpl("SHA384withRSA", "VaultSignature$SHA384RSA");
        put("Alg.Alias.Signature.SHA384withRSAEncryption", "SHA384withRSA");
        put("Alg.Alias.Signature.SHA384/RSA", "SHA384withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", "SHA384withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.113549.1.1.1",
                "SHA384withRSA");

        putSignatureImpl("SHA512withRSA", "VaultSignature$SHA512RSA");
        put("Alg.Alias.Signature.SHA512withRSAEncryption", "SHA512withRSA");
        put("Alg.Alias.Signature.SHA512/RSA", "SHA512withRSA");
        put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512withRSA");
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", "SHA512withRSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.113549.1.1.1",
                "SHA512withRSA");

        putSignatureImpl("SHA1withECDSA", "VaultSignature$SHA1ECDSA");
        put("Alg.Alias.Signature.ECDSA", "SHA1withECDSA");
        put("Alg.Alias.Signature.ECDSAwithSHA1", "SHA1withECDSA");
        put("Alg.Alias.Signature.1.2.840.10045.4.1", "SHA1withECDSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10045.2.1", "SHA1withECDSA");

        putSignatureImpl("SHA224withECDSA", "VaultSignature$SHA224ECDSA");
        put("Alg.Alias.Signature.SHA224/ECDSA", "SHA224withECDSA");
        put("Alg.Alias.Signature.1.2.840.10045.4.3.1", "SHA224withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.1", "SHA224withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.4with1.2.840.10045.2.1", "SHA224withECDSA");

        putSignatureImpl("SHA256withECDSA", "VaultSignature$SHA256ECDSA");
        put("Alg.Alias.Signature.SHA256/ECDSA", "SHA256withECDSA");
        put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.2", "SHA256withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.1with1.2.840.10045.2.1", "SHA256withECDSA");

        putSignatureImpl("SHA384withECDSA", "VaultSignature$SHA384ECDSA");
        put("Alg.Alias.Signature.SHA384/ECDSA", "SHA384withECDSA");
        put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.3", "SHA384withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.2with1.2.840.10045.2.1", "SHA384withECDSA");

        putSignatureImpl("SHA512withECDSA", "VaultSignature$SHA512ECDSA");
        put("Alg.Alias.Signature.SHA512/ECDSA", "SHA512withECDSA");
        put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.4", "SHA512withECDSA");
        put("Alg.Alias.Signature.2.16.840.1.101.3.4.2.3with1.2.840.10045.2.1", "SHA512withECDSA");

        putSignatureImpl("SHA1withRSA/PSS", "VaultSignature$SHA1RSAPSS");
        put("Alg.Alias.Signature.SHA1withRSAandMGF1", "SHA1withRSA/PSS");

        putSignatureImpl("SHA224withRSA/PSS", "VaultSignature$SHA224RSAPSS");
        put("Alg.Alias.Signature.SHA224withRSAandMGF1", "SHA224withRSA/PSS");

        putSignatureImpl("SHA256withRSA/PSS", "VaultSignature$SHA256RSAPSS");
        put("Alg.Alias.Signature.SHA256withRSAandMGF1", "SHA256withRSA/PSS");

        putSignatureImpl("SHA384withRSA/PSS", "VaultSignature$SHA384RSAPSS");
        put("Alg.Alias.Signature.SHA384withRSAandMGF1", "SHA384withRSA/PSS");

        putSignatureImpl("SHA512withRSA/PSS", "VaultSignature$SHA512RSAPSS");
        put("Alg.Alias.Signature.SHA512withRSAandMGF1", "SHA512withRSA/PSS");

        // java.security.KeyStore
        put("KeyStore.VaultKeyStore", PREFIX + "VaultKeyStoreSpi");

        Map<String, String> attributes = new HashMap<>();
        attributes.put("VAULT_ADDR", address);

        putService(new VaultKeyStoreService(this, "KeyStore", "VaultKeystore", PREFIX + "VaultKeyStoreSpi", null, attributes));
    }

    private void putSignatureImpl(String algorithm, String implClass) {
        put("Signature." + algorithm, PREFIX + implClass);
    }

    private static final class VaultKeyStoreService extends Provider.Service {

        public VaultKeyStoreService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes) {
            super(provider, type, algorithm, className, aliases, attributes);
        }

        @Override
        public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
            String type = getType();
            String algo = getAlgorithm();
            try {
                if (type.equals("KeyStore")) {
                    if (algo.equals("VaultKeystore")) {
                        String addr = getAttribute("VAULT_ADDR");
                        Client client = new VaultClient(addr);
                        return new VaultKeyStoreSpi(client);
                    }
                }
            } catch (Exception ex) {
                throw new NoSuchAlgorithmException(
                        "Error constructing " + type + " for " + algo + " using VaultProvider", ex);
            }
            throw new ProviderException("No impl for " + algo + " " + type);
        }
    }
}
