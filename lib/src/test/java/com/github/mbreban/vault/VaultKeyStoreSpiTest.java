package com.github.mbreban.vault;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class VaultKeyStoreSpiTest {

    @Mock
    Client mockClient;

    VaultKeyStoreSpi ks;

    static Keyset rsaKeyset;
    static VaultKey rsaVaultKey;

    @BeforeAll
    static void initAll() {
        rsaKeyset = new Keyset.RSA2048();

        try {
            rsaVaultKey = rsaKeyset.getVaultKey(null);
        } catch (VaultException e) {
            e.printStackTrace();
        }
    }

    @BeforeEach
    void initEach() {
        ks = new VaultKeyStoreSpi(mockClient);
    }

    @AfterEach
    void tearDown() {
    }

    @AfterAll
    static void tearDownAll() {
    }

    @Test
    void testEngineAliases() {
        List<String> keyList = Arrays.asList("foo", "bar", "baz");
        when(mockClient.list()).thenReturn(keyList);

        Enumeration<String> aliases = ks.engineAliases();
        List<String> aliasList = Collections.list(aliases);
        assertEquals(aliasList, keyList);
    }

    @Test
    void testEngineContainsAliasShouldSucceed() {
        when(mockClient.read(rsaKeyset.getName())).thenReturn(rsaVaultKey);

        Boolean present = ks.engineContainsAlias(rsaKeyset.getName());
        assertTrue(present);
    }

    @Test
    void testEngineContainsAliasShouldFailWhenKeyNotFound() {
        Boolean present = ks.engineContainsAlias("foo");
        assertFalse(present);
    }

    @Test
    void testEngineDeleteEntry() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineDeleteEntry(rsaKeyset.getName());
        });
    }

    @Test
    void testEngineGetCertificateShouldSucceed() {
        when(mockClient.read(rsaKeyset.getName())).thenReturn(rsaVaultKey);

        Certificate expCert = rsaKeyset.getCertificate();
        Certificate cert = ks.engineGetCertificate(rsaKeyset.getName());
        assertEquals(expCert, cert);
    }

    @Test
    void testEngineGetCertificateShouldFailWhenKeyNotFound() {
        Certificate cert = ks.engineGetCertificate(rsaKeyset.getName());
        assertEquals(null, cert);
    }

    @Test
    void testEngineGetCertificateAlias() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineGetCertificateAlias(null);
        });
    }

    @Test
    void testEngineGetCertificateChainShouldSucceed() {
        when(mockClient.read(rsaKeyset.getName())).thenReturn(rsaVaultKey);

        Certificate[] expCerts = rsaKeyset.getCertificateChain();
        Certificate[] certs = ks.engineGetCertificateChain(rsaKeyset.getName());
        assertArrayEquals(expCerts, certs);
    }

    @Test
    void testEngineGetCertificateChainShouldFailWhenKeyNotFound() {
        Certificate[] crts = ks.engineGetCertificateChain(rsaKeyset.getName());
        assertArrayEquals(null, crts);
    }

    @Test
    void testEngineGetCreationDateShouldSucceed() {
        when(mockClient.read(rsaKeyset.getName())).thenReturn(rsaVaultKey);

        Date date = ks.engineGetCreationDate(rsaKeyset.getName());
        assertEquals(Keyset.rsaCreationTimeDate, date);
    }

    @Test
    void testEngineGetCreationDateShouldFailWhenKeyNotFound() {
        Date date = ks.engineGetCreationDate(rsaKeyset.getName());
        assertEquals(null, date);
    }

    @Test
    void testEngineGetKeyShouldSucceed() {
        when(mockClient.read(rsaKeyset.getName())).thenReturn(rsaVaultKey);

        try {
            Key key = ks.engineGetKey(rsaKeyset.getName(), null);
            assertEquals(rsaVaultKey, key);
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            fail("Failed to get key");
        }
    }

    @Test
    void testEngineGetKeyShouldFailWhenKeyNotFound() {
        UnrecoverableKeyException thrown = Assertions.assertThrows(UnrecoverableKeyException.class, () -> {
            ks.engineGetKey("foo", null);
        });
        assertEquals("Key \"foo\" not found", thrown.getMessage());
    }

    @Test
    void testEngineIsCertificateEntry() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineIsCertificateEntry(rsaKeyset.getName());
        });
    }

    @Test
    void testEngineIsKeyEntryShouldSucceed() {
        when(mockClient.read(rsaKeyset.getName())).thenReturn(rsaVaultKey);

        Boolean present = ks.engineContainsAlias(rsaKeyset.getName());
        assertTrue(present);
    }

    @Test
    void testEngineIsKeyEntryShouldFailWhenKeyNotFound() {
        Boolean present = ks.engineContainsAlias(rsaKeyset.getName());
        assertFalse(present);
    }

    @Test
    void testEngineLoadShouldSucceed() {
        VaultStatus status = new VaultStatus.Builder()
                .setInitialized(true)
                .setSealed(false)
                .setVersion("1.15")
                .build();

        try {
            when(mockClient.status()).thenReturn(status);
        } catch (VaultException e) {
            e.printStackTrace();
        }

        try {
            ks.engineLoad(null, null);
            ks.engineLoad(null, "password".toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
            fail("Failed to load keystore");
        }
    }

    @Test
    void testEngineLoadShouldFailWhenNotInitialized() {
        VaultStatus status = new VaultStatus.Builder()
                .setInitialized(false)
                .setSealed(false)
                .setVersion("1.15")
                .build();

        try {
            when(mockClient.status()).thenReturn(status);
        } catch (VaultException e) {
            e.printStackTrace();
        }

        IOException thrown = Assertions.assertThrows(IOException.class, () -> {
            ks.engineLoad(null, null);
            ks.engineLoad(null, "password".toCharArray());
        });
        assertEquals("Vault is not initialized", thrown.getMessage());
    }

    @Test
    void testEngineLoadShouldFailWhenSealed() {
        VaultStatus status = new VaultStatus.Builder()
                .setInitialized(true)
                .setSealed(true)
                .setVersion("1.15")
                .build();

        try {
            when(mockClient.status()).thenReturn(status);
        } catch (VaultException e) {
            e.printStackTrace();
        }

        IOException thrown = Assertions.assertThrows(IOException.class, () -> {
            ks.engineLoad(null, null);
            ks.engineLoad(null, "password".toCharArray());
        });
        assertEquals("Vault is sealed", thrown.getMessage());
    }

    @Test
    void testEngineLoadShouldFailWhenOldVersion() {
        VaultStatus status = new VaultStatus.Builder()
                .setInitialized(true)
                .setSealed(false)
                .setVersion("1.14")
                .build();

        try {
            when(mockClient.status()).thenReturn(status);
        } catch (VaultException e) {
            e.printStackTrace();
        }

        IOException thrown = Assertions.assertThrows(IOException.class, () -> {
            ks.engineLoad(null, null);
            ks.engineLoad(null, "password".toCharArray());
        });
        assertEquals("Vault version is too old; use version 1.15 or higher", thrown.getMessage());
    }

    @Test
    void testEngineSetCertificateEntry() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineSetCertificateEntry(rsaKeyset.getName(), null);
        });
    }

    @Test
    void testEngineSetKeyEntry() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineSetKeyEntry(rsaKeyset.getName(), null, null);
        });
    }

    @Test
    void testEngineSize() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineSize();
        });
    }

    @Test
    void testEngineStore() {
        Assertions.assertThrows(UnsupportedOperationException.class, () -> {
            ks.engineStore(null);
        });
    }
}
