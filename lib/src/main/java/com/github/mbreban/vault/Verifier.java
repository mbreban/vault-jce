package com.github.mbreban.vault;

public interface Verifier {

    public Boolean verify(byte[] hash, String hashAlgorithm, String signatureAlgorithm, byte[] signature) throws VaultException;

}
