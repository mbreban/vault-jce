package com.github.mbreban.vault;

import java.security.NoSuchAlgorithmException;
import java.util.Locale;

final class HashAlgorithmRef {

    static String getVaultDigestAlgorithmFromStandardName(String name)
            throws NoSuchAlgorithmException {
        String algorithmUpper = name.toUpperCase(Locale.US);
        switch (algorithmUpper) {
            case SHA2_256.JCA_NAME:
                return SHA2_256.VAULT_NAME;
            case SHA2_512.JCA_NAME:
                return SHA2_512.VAULT_NAME;
            case SHA1.JCA_NAME:
                return SHA1.VAULT_NAME;
            case SHA2_384.JCA_NAME:
                return SHA2_384.VAULT_NAME;
            case SHA2_224.JCA_NAME:
                return SHA2_224.VAULT_NAME;
            case SHA3_224.JCA_NAME:
                return SHA3_224.VAULT_NAME;
            case SHA3_256.JCA_NAME:
                return SHA3_256.VAULT_NAME;
            case SHA3_384.JCA_NAME:
                return SHA3_384.VAULT_NAME;
            case SHA3_512.JCA_NAME:
                return SHA3_512.VAULT_NAME;
            default:
                throw new NoSuchAlgorithmException("Unsupported algorithm: " + name);
        }
    }

    static String getJcaDigestAlgorithmStandardNameFromVaultName(String name)
            throws NoSuchAlgorithmException {
        switch (name) {
            case SHA1.VAULT_NAME:
                return SHA1.JCA_NAME;
            case SHA2_224.VAULT_NAME:
                return SHA2_224.JCA_NAME;
            case SHA2_256.VAULT_NAME:
                return SHA2_256.JCA_NAME;
            case SHA2_384.VAULT_NAME:
                return SHA2_384.JCA_NAME;
            case SHA2_512.VAULT_NAME:
                return SHA2_512.JCA_NAME;
            case SHA3_224.VAULT_NAME:
                return SHA3_224.JCA_NAME;
            case SHA3_256.VAULT_NAME:
                return SHA3_256.JCA_NAME;
            case SHA3_384.VAULT_NAME:
                return SHA3_384.JCA_NAME;
            case SHA3_512.VAULT_NAME:
                return SHA3_512.JCA_NAME;
            default:
                throw new NoSuchAlgorithmException("Unsupported algorithm: " + name);
        }
    }

    static final class SHA1 {

        static final String JCA_NAME = "SHA-1";
        static final String VAULT_NAME = "sha1";

        private SHA1() {
        }
    }

    static final class SHA2_224 {

        static final String JCA_NAME = "SHA-224";
        static final String VAULT_NAME = "sha2-224";

        private SHA2_224() {
        }
    }

    static final class SHA2_256 {

        static final String JCA_NAME = "SHA-256";
        static final String VAULT_NAME = "sha2-256";

        private SHA2_256() {
        }
    }

    static final class SHA2_384 {

        static final String JCA_NAME = "SHA-384";
        static final String VAULT_NAME = "sha2-384";

        private SHA2_384() {
        }
    }

    static final class SHA2_512 {

        static final String JCA_NAME = "SHA-512";
        static final String VAULT_NAME = "sha2-512";

        private SHA2_512() {
        }
    }

    static final class SHA3_224 {

        static final String JCA_NAME = "SHA3-224";
        static final String VAULT_NAME = "sha3-224";

        private SHA3_224() {
        }
    }

    static final class SHA3_256 {

        static final String JCA_NAME = "SHA3-256";
        static final String VAULT_NAME = "sha3-256";

        private SHA3_256() {
        }
    }

    static final class SHA3_384 {

        static final String JCA_NAME = "SHA3-384";
        static final String VAULT_NAME = "sha3-384";

        private SHA3_384() {
        }
    }

    static final class SHA3_512 {

        static final String JCA_NAME = "SHA3-512";
        static final String VAULT_NAME = "sha3-512";

        private SHA3_512() {
        }
    }
}
