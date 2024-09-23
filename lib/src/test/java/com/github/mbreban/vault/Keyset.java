package com.github.mbreban.vault;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import com.github.mbreban.vault.VaultKey.Builder;

public class Keyset {

    static String caCert = """
-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUeHuG0eCUvRHMNdOS7ufv7+GVkLMwCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDBaFw0y
NDEwMjMxMzMxNDBaMBsxGTAXBgNVBAMMEHJvb3QtY29tbW9uLW5hbWUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATV4QcAcTIPWTbEpQD5mZ9r1Df3DLk+ujN0Ttoe
xyHROKwdPyAJ52A9Z3fr9PY0eUFfR8qsyPgV5byhroUNZqrPo1MwUTAdBgNVHQ4E
FgQUFE42x2g1YTkasYnbb73XPRJVzyUwHwYDVR0jBBgwFoAUFE42x2g1YTkasYnb
b73XPRJVzyUwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDBANIADBFAiB9Q8tR
EnG1H3M3Z73MvyRZ+hBlDw0tUtteyG39CSLNyQIhAIWmsKFUFInZm32oZL3ngKTx
GNnJXMYTMElmYV4Glkgq
-----END CERTIFICATE-----
""";

    static String keyCreationTime = "2024-09-10T12:41:48.827291072+02:00";
    static Date rsaCreationTimeDate;

    String name;
    String type;
    Certificate certificate;
    Certificate root;
    PublicKey publicKey;

    public Keyset(String name, String type, String certificate, String ca) {
        Certificate[] certs = parsePEMCertificates(certificate, ca);

        this.name = name;
        this.type = type;

        if (certs.length > 0) {
            this.certificate = certs[0];
            this.publicKey = certs[0].getPublicKey();
        }
        if (certs.length > 1) {
            this.root = certs[1];
        }
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public Certificate[] getCertificateChain() {
        List<Certificate> chain = new ArrayList<>();
        if (certificate != null) {
            chain.add(certificate);
        }
        if (root != null) {
            chain.add(root);
        }
        return chain.toArray(new Certificate[0]);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    VaultKey getVaultKey(Client client) throws VaultException {
        Certificate[] certificates = getCertificateChain();
        String certChain = encodeCertificatesPEM(certificates);
        String pemPublicKey = encodePEMString(publicKey);

        Map<String, String> one = new HashMap<>();
        one.put("certificate_chain", certChain);
        one.put("creation_time", keyCreationTime);
        one.put("name", type);
        one.put("public_key", pemPublicKey);

        Map<String, Object> rsaKeys = new HashMap<>();
        rsaKeys.put("1", one);

        Builder builder = new VaultKey.Builder()
                .setName(name)
                .setType(type)
                .setKeys(rsaKeys)
                .setLatestVersion(1);

        if (client != null) {
            builder.setClient(client);
        }

        return builder.build();
    }

    private String encodePEMString(PublicKey publicKey) {
        StringWriter writer = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(writer)) {
            PemObject gen = new PemObject("PUBLIC KEY", publicKey.getEncoded());
            pemWriter.writeObject(gen);
            pemWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return writer.toString();
    }

    private String encodeCertificatesPEM(Certificate[] certs) {
        StringWriter writer = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(writer)) {
            for (Certificate cert : certs) {
                PemObject gen = new PemObject("CERTIFICATE", cert.getEncoded());
                pemWriter.writeObject(gen);
            }
            pemWriter.flush();
        } catch (IOException | CertificateEncodingException e) {
            e.printStackTrace();
        }
        return writer.toString();
    }

    private Certificate[] parsePEMCertificates(String... pemCert) {
        String chain = String.join("\n", pemCert);
        byte[] bytes = Strings.toByteArray(chain);

        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Collection<Certificate> certs = (Collection<Certificate>) certFactory.generateCertificates(new ByteArrayInputStream(bytes));
            return certs.toArray(new Certificate[0]);
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    Date parseDateISO8601(String str) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            return sdf.parse(str);
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static final class RSA2048 extends Keyset {

        static String leaf = """
-----BEGIN CERTIFICATE-----
MIICQTCCAeagAwIBAgIUA79ZxtwqByWUaUoLG/M5yn3kQGUwCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDFaFw0y
NDA5MzAxMzMxNDFaMBYxFDASBgNVBAMMC215LXJzYS0yMDQ4MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7iOy3/v9+rVQhgBz+BDthweUU/J0JQ4zyrOr
np0v74bij7eTMD4BWGhonnKmcX5o2TH6SGVdGsQTH+1A7V5OZL6DTH+Qqpf4VkMZ
n3VsYF1XyS1suY3GvKs22zmK3E1Jss7SO5g4Om7Jnw+jlHS4eQ+qRtlogqE3TGP6
Uks1I7lHZAn2EVPtLrSlDRK1DSbJxfvoJjbbQ2w56SFJE0EH4cPDRmqtGXgKJscy
cRFTNn8M8IDmKrbSejGtU4opyMPoyB76nBxn7bXgmuBhOf2K42Cml/wwgOH4ufwx
6nB57crsFqY195AJLMv9j//QlIPVN/H4bvRVWGIEGADLkZ00cQIDAQABo0IwQDAd
BgNVHQ4EFgQUZIUKxxsxMj7xZt3IdyQfaOk6JI0wHwYDVR0jBBgwFoAUFE42x2g1
YTkasYnbb73XPRJVzyUwCgYIKoZIzj0EAwQDSQAwRgIhAPnV1rEBR87GIndky2Bj
Y+HSTq/IXSqD4gxxZj8Ks1SrAiEAji5T6zKRe210gYKgUCVHCljy02rUPIyNdLda
i0aflZo=
-----END CERTIFICATE-----
""";

        public RSA2048() {
            super("my-rsa-2048", "rsa-2048", leaf, caCert);
        }
    }

    public static final class RSA3072 extends Keyset {

        static String leaf = """
-----BEGIN CERTIFICATE-----
MIICwDCCAmagAwIBAgIUA79ZxtwqByWUaUoLG/M5yn3kQGYwCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDJaFw0y
NDA5MzAxMzMxNDJaMBYxFDASBgNVBAMMC215LXJzYS0zMDcyMIIBojANBgkqhkiG
9w0BAQEFAAOCAY8AMIIBigKCAYEAzuaJp+LKbO8ENJa4P9SGXO4gEz3Hwng4c37i
qwsiYRQYvdohTKTznCWFCscCQtjFJeflNyTR92RFKUTtbluoGVXJDYLNNrqeYUpr
S3HxqJg8Xa+zcD+fHqiyC8pjQ93jLxQxfCcSZK8JvBgB7Vhh5EEGSJmWhmj3gm2O
czlOn4lleQYJtLoYpZp+fhXJB+tjown8PRu5WZOSlU0zDiyqutnfSxWpjIE3x8Mq
gPbcAeToeTLX/TPl/AIGbZ5hECr08OEXHfKHtDOlndPuI89YJtiqa5b3rgDPmdeL
fFyvzp1wYgNSeSHkOoNio4SBCAYhGIHRd6J3yc9olOkSK3sfrw8pjwq7vTEaNoM+
VbVfCbjPfVTQoT2b0SVL2vDLiG5K4hR4i3Eyo2qVqkPaiU8YT//wa4f4pjqzOcNS
ISxrKZ/aGELTAgpmYRK1/iCZlbs5ZPs7nWL+ttQzCxs0F6YS9z8b25MhIPsCHIBK
VDBvefFFLC+DQxOWT7KXKtp4Z6dxAgMBAAGjQjBAMB0GA1UdDgQWBBT+W0QneGrU
04XlB0MeOfUXxA3w2DAfBgNVHSMEGDAWgBQUTjbHaDVhORqxidtvvdc9ElXPJTAK
BggqhkjOPQQDBANIADBFAiARwbVGWjgKjsbXy1kVY3cEfV4OQExG8D8PxNqIRTAH
UgIhAPW4ieYOL42FD7kVxQ/c8VNoowI+hJGglq69tn962CvL
-----END CERTIFICATE-----
""";

        public RSA3072() {
            super("my-rsa-3072", "rsa-3072", leaf, caCert);
        }
    }

    public static final class RSA4096 extends Keyset {

        static String leaf = """
-----BEGIN CERTIFICATE-----
MIIDQDCCAuagAwIBAgIUA79ZxtwqByWUaUoLG/M5yn3kQGcwCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDNaFw0y
NDA5MzAxMzMxNDNaMBYxFDASBgNVBAMMC215LXJzYS00MDk2MIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0bviulcKyaEiID+MZ7cvIO3z5J6ktkF1+Mgm
En6EhYLHIbw5zjGDjdpCUEz7Znx0eiNZ4t3k7BxkNDy6c+NGHvXHSFXoFyQkWdjc
AvfFE59KZrrTIYlAIt67epxfTidYhMPvuzbyx0moKuHS7vf2hS50tUYHnDojZ1BY
yMvEzErJ9a0ASMvt8+nCUNxF0nMzAX33tTu3AlZiuxcvoZrljKJSNxYj076uHXn3
IsqD9U3C8RH28MUvwFEn497vx5bOpcBc7TmJOIWjxFErJk9aR8gP2g+xJWexHZNV
JgzWAL1NhrceLguAT9y5EJhBAiWcWchFdJFkUrFRixRAOXtFY//fMQN884XwqM6e
VDeDKAPrFJR4pgIE3METCt2HvHi+rMe3mQnuFvWTA8KThv+AdPIxHO5WuvrM+kbO
aeKHz9+wOGe5vBCjXe9BCkyn4q+uBRcKsnf/cCqsh8v2HxytmnEOYBs5F1OJqrjY
KEWa1D/rnUEGJGcF+qdETE02xHooWCP+LGu7GnytOdD3UMMVuqyeVtIPieqPg8oL
ra9xMapkaY/NPZqdbiPqt6CVoFc5aLH3RR+jN9UWmmeKGvRqxh8QyyU/DMC5dKLc
3Hhg9k3AALGHdt+w3DlzFgxGMxDzNnr9U3aOx0/4rScxZzATe477xhYyJnQJ4uOn
dGR7Ps0CAwEAAaNCMEAwHQYDVR0OBBYEFNjRi1AnjTec37VYwk74g9X/DiOmMB8G
A1UdIwQYMBaAFBRONsdoNWE5GrGJ22+91z0SVc8lMAoGCCqGSM49BAMEA0gAMEUC
IGbzYb5tWKeE9EY6K6xgxR69mz3I5W/9d7CxL6328fqsAiEA6K72tYEhrt7G4Gog
B1HsRuKy9HDRPNAiFxoDXvePoN0=
-----END CERTIFICATE-----
""";

        public RSA4096() {
            super("my-rsa-4096", "rsa-4096", leaf, caCert);
        }
    }

    public static final class ECDSAP256 extends Keyset {

        static String leaf = """
-----BEGIN CERTIFICATE-----
MIIBeDCCAR2gAwIBAgIUA79ZxtwqByWUaUoLG/M5yn3kQGgwCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDNaFw0y
NDA5MzAxMzMxNDNaMBgxFjAUBgNVBAMMDW15LWVjZHNhLXAyNTYwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAATD0lWoXjUbAScvKt3pIisa8QjnYAC9s/CYBz+nBucd
pzP2XgC2fbDfRoeWpgJZdcZllv7MJ1rCfRng3h6V/sMLo0IwQDAdBgNVHQ4EFgQU
+1dPktegWCDgJxurg/d5A92ZMJgwHwYDVR0jBBgwFoAUFE42x2g1YTkasYnbb73X
PRJVzyUwCgYIKoZIzj0EAwQDSQAwRgIhAJW9h2z0jZqssIAOLL4gL2j44ni4Q8qg
YwEvZvt0XdXeAiEAz5K3NGv1vvBp65tjN5Ih0KtWiMWC+ePDmUYrQy4o2xs=
-----END CERTIFICATE-----
""";

        public ECDSAP256() {
            super("my-ecdsa-p256", "ecdsa-p256", leaf, caCert);
        }
    }

    public static final class ECDSAP384 extends Keyset {

        static String leaf = """
-----BEGIN CERTIFICATE-----
MIIBlDCCATqgAwIBAgIUA79ZxtwqByWUaUoLG/M5yn3kQGkwCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDNaFw0y
NDA5MzAxMzMxNDNaMBgxFjAUBgNVBAMMDW15LWVjZHNhLXAzODQwdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAAT5IKtsUtI/5VdakqbsfTmiTV4SMOwEXXBt55DrNypetrWW
zPOIikvkXBfyvrTYrBSaqbIF0vib0MmS3FX+6w/oI0MKu1hjInMHEfuXT9nXru9Z
VSAdfoue3QTpDV4HD9qjQjBAMB0GA1UdDgQWBBQB2wGZFhhgbXmfDpfnEwcHQx6T
HjAfBgNVHSMEGDAWgBQUTjbHaDVhORqxidtvvdc9ElXPJTAKBggqhkjOPQQDBANI
ADBFAiEAodkoVKwlZT4io/OP41nyhRPYmzS/4HuCufo6jyKEYTkCIBfBERjwMXNE
yWOvL7TvqGp9PdReeqhKadTtpjOCelj+
-----END CERTIFICATE-----
""";

        public ECDSAP384() {
            super("my-ecdsa-p384", "ecdsa-p384", leaf, caCert);
        }
    }

    public static final class ECDSAP521 extends Keyset {

        static String leaf = """
-----BEGIN CERTIFICATE-----
MIIBuzCCAWCgAwIBAgIUA79ZxtwqByWUaUoLG/M5yn3kQGowCgYIKoZIzj0EAwQw
GzEZMBcGA1UEAwwQcm9vdC1jb21tb24tbmFtZTAeFw0yNDA5MjMxMzMxNDRaFw0y
NDA5MzAxMzMxNDRaMBgxFjAUBgNVBAMMDW15LWVjZHNhLXA1MjEwgZswEAYHKoZI
zj0CAQYFK4EEACMDgYYABAC5R91HbdM9aAC5gUgBC+FI9ccPKW4CHYYdUzXKGyuh
/g+6DCKSMRp12ZGMp9rrBS2JF1vjdaD6rbLJIu1PDcxN5gFzP7HxwqIc+F4opAgQ
KV21BGA3pPbcEkV3+hHwy3VzKC/irLM40HNO62W+i7QPaDsvkPJ0fFKEsnBx5w8p
1FElc6NCMEAwHQYDVR0OBBYEFEhw8DIKHWdEc9Ks/ip/VJQWMNuUMB8GA1UdIwQY
MBaAFBRONsdoNWE5GrGJ22+91z0SVc8lMAoGCCqGSM49BAMEA0kAMEYCIQCRrscK
paMcaMQdoxz/JxHH3yzz755Fl1Ivucb3+PxyugIhAOzoND9y8IasllljseAEY4OJ
tPjbaubkA2Ke5ySf0QtX
-----END CERTIFICATE-----
""";

        public ECDSAP521() {
            super("my-ecdsa-p521", "ecdsa-p521", leaf, caCert);
        }
    }
}
