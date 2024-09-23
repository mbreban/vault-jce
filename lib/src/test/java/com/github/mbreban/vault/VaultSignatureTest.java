package com.github.mbreban.vault;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class VaultSignatureTest {

    @Mock
    Client mockClient;

    private final byte[] emptyArray = new byte[0];

    static Keyset rsaKeyset;
    static Keyset ecdsaKeyset;

    @BeforeAll
    static void initAll() {
        rsaKeyset = new Keyset.RSA2048();
        ecdsaKeyset = new Keyset.ECDSAP256();
    }

    @BeforeEach
    void initEach() {
    }

    @AfterEach
    void tearDown() {
    }

    @AfterAll
    static void tearDownAll() {
    }

    @Test
    void testEngineGetParameter() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineGetParameter("");
        });
    }

    @Test
    void testEngineInitSignShouldSucceed() {
        try {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(key);
        } catch (NoSuchAlgorithmException | InvalidKeyException | VaultException e) {
            fail("Failed to init sign: " + e.getMessage());
        }
    }

    @Test
    void testEngineInitSignShouldFailWhenTypeIsInvalid() {
        InvalidKeyException thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1ECDSA();
            signature.engineInitSign(key);
        });
        assertEquals("Signature initialized as EC (not RSA)", thrown.getMessage());

        thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultKey key = ecdsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(key);
        });
        assertEquals("Signature initialized as RSA (not EC)", thrown.getMessage());
    }

    @Test
    void testEngineInitSignShouldFailWhenClassIsInvalid() {
        PrivateKey mockPrivateKey = mock(PrivateKey.class);

        InvalidKeyException thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1ECDSA();
            signature.engineInitSign(mockPrivateKey);
        });
        assertEquals("Invalid key type; expected VaultKey", thrown.getMessage());
    }

    @Test
    void testEngineInitSignShouldFailWhenKeyIsNull() {
        InvalidKeyException thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(null);
        });
        assertEquals("Key is null", thrown.getMessage());
    }

    @Test
    void testEngineInitVerifyShouldSucceed() {
        try {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitVerify(key);
        } catch (NoSuchAlgorithmException | InvalidKeyException | VaultException e) {
            fail("Failed to init verify: " + e.getMessage());
        }
    }

    @Test
    void testEngineInitVerifyShouldFailWhenTypeIsInvalid() {
        InvalidKeyException thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1ECDSA();
            signature.engineInitVerify(key);
        });
        assertEquals("Signature initialized as EC (not RSA)", thrown.getMessage());

        thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultKey key = ecdsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitVerify(key);
        });
        assertEquals("Signature initialized as RSA (not EC)", thrown.getMessage());
    }

    @Test
    void testEngineInitVerifyShouldFailWhenClassIsInvalid() {
        PublicKey mockPublicKey = mock(PublicKey.class);

        InvalidKeyException thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1ECDSA();
            signature.engineInitVerify(mockPublicKey);
        });
        assertEquals("Invalid key type; expected VaultKey", thrown.getMessage());
    }

    @Test
    void testEngineInitVerifyShouldFailWhenKeyIsNull() {
        InvalidKeyException thrown = Assertions.assertThrows(InvalidKeyException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitVerify(null);
        });
        assertEquals("Key is null", thrown.getMessage());
    }

    @Test
    void testEngineSetParameter() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineSetParameter("", null);
        });
    }

    @Test
    void testEngineSignShouldSucceed() {
        try {
            byte[] emptyArray = new byte[0];
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] emptyArrayDigest = md.digest(emptyArray);

            when(mockClient.sign(rsaKeyset.getName(), emptyArrayDigest, "sha1", "pkcs1v15", true, "")).thenReturn(emptyArray);

            VaultKey key = rsaKeyset.getVaultKey(mockClient);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(key);

            signature.engineUpdate(emptyArray, 0, emptyArray.length);

            byte[] bytes = signature.engineSign();
            assertArrayEquals(emptyArray, bytes);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to sign: " + e.getMessage());
        }
    }

    @Test
    void testEngineSignShouldSucceedWithEmptyMessage() {
        try {
            byte[] emptyArray = new byte[0];
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] emptyArrayDigest = md.digest(emptyArray);

            when(mockClient.sign(rsaKeyset.getName(), emptyArrayDigest, "sha1", "pkcs1v15", true, "")).thenReturn(emptyArray);

            VaultKey key = rsaKeyset.getVaultKey(mockClient);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(key);

            byte[] bytes = signature.engineSign();
            assertArrayEquals(emptyArray, bytes);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to sign: " + e.getMessage());
        }
    }

    @Test
    void testEngineSignShouldFailWhenNotInitialized() {
        SignatureException thrown = Assertions.assertThrows(SignatureException.class, () -> {
            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineSign();
        });
        assertEquals("Engine not initialized", thrown.getMessage());
    }

    @Test
    void testEngineUpdate_3argsShouldSucceedWhenSigning() {
        try {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(key);

            signature.engineUpdate(emptyArray, 0, emptyArray.length);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to update: " + e.getMessage());
        }
    }

    @Test
    void testEngineUpdate_3argsShouldSucceedWhenVerifying() {
        try {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitVerify(key);

            signature.engineUpdate(emptyArray, 0, emptyArray.length);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to update: " + e.getMessage());
        }
    }

    @Test
    void testEngineUpdate_1arg() {
        try {
            VaultKey key = rsaKeyset.getVaultKey(null);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitSign(key);

            signature.engineUpdate((byte)0x00);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to update: " + e.getMessage());
        }
    }

    @Test
    void testEngineVerifyShouldSucceed() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] emptyArrayDigest = md.digest(emptyArray);

            when(mockClient.verify(rsaKeyset.getName(), emptyArrayDigest, "sha1", "pkcs1v15", true, emptyArray)).thenReturn(true);

            VaultKey key = rsaKeyset.getVaultKey(mockClient);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitVerify(key);

            Boolean verdict = signature.engineVerify(emptyArray);
            assertTrue(verdict);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to verify: " + e.getMessage());
        }
    }

    @Test
    void testEngineVerifyShouldSucceedWithEmptyMessage() {
        try {
            byte[] emptyArray = new byte[0];
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] emptyArrayDigest = md.digest(emptyArray);
            

            when(mockClient.verify(rsaKeyset.getName(), emptyArrayDigest, "sha1", "pkcs1v15", true, emptyArray)).thenReturn(true);

            VaultKey key = rsaKeyset.getVaultKey(mockClient);

            VaultSignature signature = new VaultSignature.SHA1RSA();
            signature.engineInitVerify(key);

            Boolean verdict = signature.engineVerify(emptyArray);
            assertTrue(verdict);
        } catch (VaultException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            fail("Failed to verify: " + e.getMessage());
        }
    }
}
