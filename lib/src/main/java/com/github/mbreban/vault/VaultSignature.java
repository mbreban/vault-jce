package com.github.mbreban.vault;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class VaultSignature extends SignatureSpi {

    private enum EngineType {
        RSA, EC,
    }

    private VaultKey key;

    private final EngineType engineType;

    private final String contentHashAlgorithm;

    private final String signatureAlgorithm;

    private final String saltLength;

    private final MessageDigest messageDigest;

    private boolean signing;

    /**
     * Creates a new VaultSignature instance for the given algorithm name.
     *
     * @param contentDigestAlgorithm the hash algorithm to use for supporting key types.
     * @param engineType the engine type to use (RSA or EC).
     * @param signatureAlgorithm the RSA signature algorithm to use for signing.
     * @param saltLength the salt length used to sign. This currently only
     * applies to the RSA PSS signature scheme. Options are: "auto", "hash".
     * @throws NoSuchAlgorithmException
     */
    private VaultSignature(String contentDigestAlgorithm, EngineType engineType, String signatureAlgorithm, String saltLength) throws NoSuchAlgorithmException {

        this.engineType = engineType;
        this.contentHashAlgorithm = contentDigestAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.saltLength = saltLength;

        String jcaDigestAlgorithm = HashAlgorithmRef.getJcaDigestAlgorithmStandardNameFromVaultName(this.contentHashAlgorithm);
        this.messageDigest = MessageDigest.getInstance(jcaDigestAlgorithm);
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("Unimplemented method 'engineGetParameter'");
    }

    private void checkEngineType(VaultKey key) throws InvalidKeyException {
        String algo = key.getAlgorithm().toLowerCase();

        switch (engineType) {
            case RSA:
                if (!algo.startsWith("rsa")) {
                    throw new InvalidKeyException("Signature initialized as " + engineType + " (not EC)");
                }
                break;
            case EC:
                if (!algo.startsWith("ecdsa")) {
                    throw new InvalidKeyException("Signature initialized as " + engineType + " (not RSA)");
                }
                break;
            default:
                throw new InvalidKeyException("Key must be of type EC or RSA");
        }
    }

    private void initInternal(VaultKey newKey, boolean signing) throws InvalidKeyException {
        checkEngineType(newKey);
        this.key = newKey;
        this.signing = signing;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        initInternal(VaultKey.fromPrivateKey(privateKey), true);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        initInternal(VaultKey.fromPublicKey(publicKey), false);
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("Unimplemented method 'engineSetParameter'");
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!signing) {
            throw new SignatureException("Engine not initialized");
        }

        final byte[] hash = this.messageDigest.digest();

        try {
            return this.key.sign(hash, this.contentHashAlgorithm, this.signatureAlgorithm, this.saltLength);
        } catch (VaultException e) {
            throw new SignatureException(e.getMessage());
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        this.messageDigest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.messageDigest.update(b, off, len);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (signing) {
            throw new SignatureException("Engine not initialized");
        }

        final byte[] hash = this.messageDigest.digest();

        try {
            return this.key.verify(hash, this.contentHashAlgorithm, this.signatureAlgorithm, sigBytes);
        } catch (VaultException e) {
            throw new SignatureException(e.getMessage());
        }
    }

    abstract static class RSAPKCS1Padding extends VaultSignature {

        public RSAPKCS1Padding(String contentDigestAlgorithm) throws NoSuchAlgorithmException {
            super(contentDigestAlgorithm, EngineType.RSA, "pkcs1v15", "");
        }
    }

    public static final class SHA1RSA extends RSAPKCS1Padding {

        public SHA1RSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA1.VAULT_NAME);
        }
    }

    public static final class SHA224RSA extends RSAPKCS1Padding {

        public SHA224RSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_224.VAULT_NAME);
        }
    }

    public static final class SHA256RSA extends RSAPKCS1Padding {

        public SHA256RSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_256.VAULT_NAME);
        }
    }

    public static final class SHA384RSA extends RSAPKCS1Padding {

        public SHA384RSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_384.VAULT_NAME);
        }
    }

    public static final class SHA512RSA extends RSAPKCS1Padding {

        public SHA512RSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_512.VAULT_NAME);
        }
    }

    abstract static class RSAPSSPadding extends VaultSignature {

        public RSAPSSPadding(String contentDigestAlgorithm, String saltLenght) throws NoSuchAlgorithmException {
            super(contentDigestAlgorithm, EngineType.RSA, "pss", saltLenght);
        }
    }

    public static final class SHA1RSAPSS extends RSAPSSPadding {

        public SHA1RSAPSS(String saltLenght) throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA1.VAULT_NAME, saltLenght);
        }

        public SHA1RSAPSS() throws NoSuchAlgorithmException {
            this("auto");
        }
    }

    public static final class SHA224RSAPSS extends RSAPSSPadding {

        public SHA224RSAPSS(String saltLenght) throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_224.VAULT_NAME, saltLenght);
        }

        public SHA224RSAPSS() throws NoSuchAlgorithmException {
            this("auto");
        }
    }

    public static final class SHA256RSAPSS extends RSAPSSPadding {

        public SHA256RSAPSS(String saltLenght) throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_256.VAULT_NAME, saltLenght);
        }

        public SHA256RSAPSS() throws NoSuchAlgorithmException {
            this("auto");
        }
    }

    public static final class SHA384RSAPSS extends RSAPSSPadding {

        public SHA384RSAPSS(String saltLenght) throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_384.VAULT_NAME, saltLenght);
        }

        public SHA384RSAPSS() throws NoSuchAlgorithmException {
            this("auto");
        }
    }

    public static final class SHA512RSAPSS extends RSAPSSPadding {

        public SHA512RSAPSS(String saltLenght) throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_512.VAULT_NAME, saltLenght);
        }

        public SHA512RSAPSS() throws NoSuchAlgorithmException {
            this("auto");
        }
    }

    abstract static class ECDSA extends VaultSignature {

        public ECDSA(String contentDigestAlgorithm) throws NoSuchAlgorithmException {
            super(contentDigestAlgorithm, EngineType.EC, "", "");
        }
    }

    public static final class SHA1ECDSA extends ECDSA {

        public SHA1ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA1.VAULT_NAME);
        }
    }

    public static final class SHA224ECDSA extends ECDSA {

        public SHA224ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_224.VAULT_NAME);
        }
    }

    public static final class SHA256ECDSA extends ECDSA {

        public SHA256ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_256.VAULT_NAME);
        }
    }

    public static final class SHA384ECDSA extends ECDSA {

        public SHA384ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_384.VAULT_NAME);
        }
    }

    public static final class SHA512ECDSA extends ECDSA {

        public SHA512ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA2_512.VAULT_NAME);
        }
    }

    public static final class SHA3224ECDSA extends ECDSA {

        public SHA3224ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA3_224.VAULT_NAME);
        }
    }

    public static final class SHA3256ECDSA extends ECDSA {

        public SHA3256ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA3_256.VAULT_NAME);
        }
    }

    public static final class SHA3384ECDSA extends ECDSA {

        public SHA3384ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA3_384.VAULT_NAME);
        }
    }

    public static final class SHA3512ECDSA extends ECDSA {

        public SHA3512ECDSA() throws NoSuchAlgorithmException {
            super(HashAlgorithmRef.SHA3_512.VAULT_NAME);
        }
    }
}
