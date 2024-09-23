package com.github.mbreban.vault;

public interface Signer {

    public byte[] sign(byte[] hash, String hashAlgorithm, String signatureAlgorithm, String saltLength) throws VaultException;

}
