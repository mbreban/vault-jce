package com.github.mbreban.vault;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.apache.maven.artifact.versioning.ComparableVersion;

public class VaultKeyStoreSpi extends KeyStoreSpi {

    private static final String MIN_VERSION = "1.15";

    private final Client client;

    public VaultKeyStoreSpi(Client client) {
        this.client = client;
    }

    @Override
    public Enumeration<String> engineAliases() {
        List<String> aliases = client.list();
        return Collections.enumeration(aliases);
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        VaultKey key = client.read(alias);
        return key != null;
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new UnsupportedOperationException("Unimplemented method 'engineDeleteEntry'");
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            Certificate[] chain = getCertificateChain(alias);
            if (chain.length > 0) {
                return chain[0];
            }
        } catch (VaultException e) {
            e.printStackTrace();
        }
        return null;
    }

    private Certificate[] getCertificateChain(String alias) throws VaultException {
        VaultKey key = client.read(alias);
        if (key == null) {
            throw new VaultException("Key \"" + alias + "\"not found");
        }

        int version = key.getLatestVersion();

        AsymetricKeyVersion kv = key.getKeyVersion(version);
        if (kv == null) {
            return new Certificate[0];
        }
        String pemCertChain = kv.getCertificateChain();

        return parseCertificateChain(pemCertChain.getBytes());
    }

    private static Certificate[] parseCertificateChain(byte[] bytes) {
        final Collection<X509Certificate> x509Certs = toCertificates(bytes);
        return x509Certs.toArray(new Certificate[0]);
    }

    private static Collection<X509Certificate> toCertificates(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (Collection<X509Certificate>) certFactory.generateCertificates(new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            return new ArrayList<>();
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        throw new UnsupportedOperationException("Unimplemented method 'engineGetCertificateAlias'");
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            return getCertificateChain(alias);
        } catch (VaultException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        VaultKey key = client.read(alias);
        if (key == null) {
            return null;
        }

        int version = key.getLatestVersion();
        AsymetricKeyVersion kv = key.getKeyVersion(version);
        return kv.getCreationTimeDate();
    }

    @Override
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        VaultKey key = client.read(alias);
        if (key == null) {
            throw new UnrecoverableKeyException("Key \"" + alias + "\" not found");
        }
        return key;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        throw new UnsupportedOperationException("Unimplemented method 'engineIsCertificateEntry'");
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return engineContainsAlias(alias);
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        if (password != null) {
            String token = String.valueOf(password);
            client.authenticate(token);
        }

        try {
            VaultStatus status = client.status();
            checkStatus(status);
        } catch (VaultException e) {
            throw new IOException(e.getMessage());
        }
    }

    private void checkStatus(VaultStatus status) throws VaultException {
        if (status ==null) {
            throw new VaultException("VaultStatus is null");
        }
        if (!status.isInitialized()) {
            throw new VaultException("Vault is not initialized");
        }
        if (status.isSealed()) {
            throw new VaultException("Vault is sealed");
        }

        ComparableVersion minVersion = new ComparableVersion(MIN_VERSION);
        ComparableVersion curVersion = new ComparableVersion(status.getVersion());

        if (curVersion.compareTo(minVersion) < 0) {
            throw new VaultException("Vault version is too old; use version " + MIN_VERSION + " or higher");
        }
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException("Unimplemented method 'engineSetCertificateEntry'");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
            throws KeyStoreException {
        throw new UnsupportedOperationException("Unimplemented method 'engineSetKeyEntry'");
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
        throw new UnsupportedOperationException("Unimplemented method 'engineSetKeyEntry'");
    }

    @Override
    public int engineSize() {
        throw new UnsupportedOperationException("Unimplemented method 'engineSize'");
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException("Unimplemented method 'engineStore'");
    }

    public Client getClient() {
        return client;
    }
}
