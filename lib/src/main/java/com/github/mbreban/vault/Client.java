package com.github.mbreban.vault;

import java.util.List;

public interface Client {

    public VaultStatus status() throws VaultException;

    public VaultKey read(String keyname);

    public List<String> list();

    /**
     * @param keyName the name of the key to use for signing.
     * @param bytes the input data.
     * @param hashAlgorithm the hash algorithm to use for supporting key types.
     * @param signatureAlgorithm the RSA signature algorithm to use for signing.
     * @param prehashed indicates whether the input is already hashed.
     * @param saltLength the salt length used to sign. This currently only
     * applies to the RSA PSS signature scheme. Options are: "auto", "hash".
     * @return the signature bytes.
     */
    public byte[] sign(String keyName, byte[] bytes, String hashAlgorithm, String signatureAlgorithm, boolean prehashed, String saltLength);

    /**
     * @param keyName the name of the key that was used to generate the signature.
     * @param plaintext the plaintext data.
     * @param hashAlgorithm the hash algorithm to use for supporting key types.
     * @param signatureAlgorithm the RSA signature algorithm to use for signing.
     * @param prehashed indicates whether the input is already hashed.
     * @param signature the signature to verify.
     * @return true if the signature is valid, false otherwise.
     */
    public boolean verify(String keyName, byte[] plaintext, String hashAlgorithm, String signatureAlgorithm, boolean prehashed, byte[] signature);

    public void authenticate(String token);

}
