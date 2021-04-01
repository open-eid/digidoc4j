package org.digidoc4j.utils;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.test.TestLog;
import org.digidoc4j.test.util.TestCertificateUtil;
import org.digidoc4j.test.util.TestKeyPairUtil;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class KeyStoreDocumentTest extends AbstractTest {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_PASSWORD = "Passw0rd";
    private static final String KEYSTORE_EXTENSION = ".p12";

    private TestLog testLog;

    @BeforeClass
    public static void setUpStatic() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    protected void before() {
        testLog = new TestLog(KeyStoreDocument.class);
    }

    @Test
    public void testKeyStoreFailsToLoadWhenNotExisting() {
        String nonExistingPath = new File(testFolder.getRoot(), "non-existing-keystore" + KEYSTORE_EXTENSION).getPath();
        Duration minValidationInterval = Duration.ofMinutes(1L);
        Period maxWarningPeriod = Period.ofDays(1);

        IllegalArgumentException caughtException = assertThrows(
                IllegalArgumentException.class,
                () -> new KeyStoreDocument(nonExistingPath, KEYSTORE_TYPE, KEYSTORE_PASSWORD, minValidationInterval, maxWarningPeriod)
        );

        Assert.assertEquals("Resource not found: " + nonExistingPath, caughtException.getMessage());
        testLog.verifyLogEmpty();
    }

    @Test
    public void testKeyStoreFailsToParseOnInvalidKeystoreType() {
        String keyStorePath = "classpath:testFiles/truststores/empty-truststore.p12";
        String invalidKeyStoreType = "INVALID";
        Duration minValidationInterval = Duration.ofMinutes(1L);
        Period maxWarningPeriod = Period.ofDays(1);

        IllegalStateException caughtException = assertThrows(
                IllegalStateException.class,
                () -> new KeyStoreDocument(keyStorePath, invalidKeyStoreType, KEYSTORE_PASSWORD, minValidationInterval, maxWarningPeriod)
        );

        Assert.assertEquals("Failed to create key-store of type: " + invalidKeyStoreType, caughtException.getMessage());
        testLog.verifyLogEmpty();
    }

    @Test
    public void testKeyStoreFailsToParseOnInvalidKeystorePassword() {
        String keyStorePath = "classpath:testFiles/truststores/empty-truststore.p12";
        String invalidKeyStorePassword = "Inval1d";
        Duration minValidationInterval = Duration.ofMinutes(1L);
        Period maxWarningPeriod = Period.ofDays(1);

        IllegalStateException caughtException = assertThrows(
                IllegalStateException.class,
                () -> new KeyStoreDocument(keyStorePath, KEYSTORE_TYPE, invalidKeyStorePassword, minValidationInterval, maxWarningPeriod)
        );

        Assert.assertEquals("Failed to load key-store from: " + keyStorePath, caughtException.getMessage());
        testLog.verifyLogEmpty();
    }

    @Test
    public void testInitialKeystoreValidationWithWarningPeriod() throws Exception {
        Instant now = Instant.now();

        Map<String, Certificate> certificates = new LinkedHashMap<>();
        certificates.put("expired-day", createTestCertificate("CN=EXPIRED-DAY", now.minus(Period.ofDays(2)), now.minus(Period.ofDays(1))));
        certificates.put("expired-minute", createTestCertificate("CN=EXPIRED-MINUTE", now.minus(Duration.ofMinutes(2L)), now.minus(Duration.ofMinutes(1L))));
        for (int i = 1; i < 9; ++i) {
            certificates.put("about-to-expire-" + i, createTestCertificate("CN=ABOUT-TO-EXPIRE-" + i, now, now.plus(Period.ofDays(i))));
        }
        certificates.put("about-to-expire-minute", createTestCertificate("CN=ABOUT-TO-EXPIRE-MINUTE", now, now.plus(Period.ofDays(9)).minus(Duration.ofMinutes(1L))));
        certificates.put("still-time-minute", createTestCertificate("CN=STILL-TIME-MINUTE", now, now.plus(Period.ofDays(9)).plus(Duration.ofMinutes(1L))));
        certificates.put("still-time-plenty", createTestCertificate("CN=STILL-TIME-PLENTY", now, now.plus(Period.ofDays(365))));

        File keyStoreFile = createTestKeyStore(certificates);
        String keyStorePath = keyStoreFile.getCanonicalPath();
        Duration minValidationInterval = Duration.ofMinutes(5L);
        Period maxWarningPeriod = Period.ofDays(9);

        KeyStoreDocument keyStoreDocument = new KeyStoreDocument(keyStorePath, KEYSTORE_TYPE, KEYSTORE_PASSWORD, minValidationInterval, maxWarningPeriod);

        String expiredTemplate = "Certificate from \"%s\" has already expired (%s) - alias: \"%s\"; subject: \"%s\"";
        String expiringTemplate = "Certificate from \"%s\" expires (%s) in about %d day(s) - alias: \"%s\"; subject: \"%s\"";
        testLog.verifyLogInOrder(
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS), "expired-day", "CN=EXPIRED-DAY")),
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Duration.ofMinutes(1L)).truncatedTo(ChronoUnit.SECONDS), "expired-minute", "CN=EXPIRED-MINUTE")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS), 8, "about-to-expire-1", "CN=ABOUT-TO-EXPIRE-1")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(2)).truncatedTo(ChronoUnit.SECONDS), 7, "about-to-expire-2", "CN=ABOUT-TO-EXPIRE-2")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(3)).truncatedTo(ChronoUnit.SECONDS), 6, "about-to-expire-3", "CN=ABOUT-TO-EXPIRE-3")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(4)).truncatedTo(ChronoUnit.SECONDS), 5, "about-to-expire-4", "CN=ABOUT-TO-EXPIRE-4")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(5)).truncatedTo(ChronoUnit.SECONDS), 4, "about-to-expire-5", "CN=ABOUT-TO-EXPIRE-5")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(6)).truncatedTo(ChronoUnit.SECONDS), 3, "about-to-expire-6", "CN=ABOUT-TO-EXPIRE-6")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(7)).truncatedTo(ChronoUnit.SECONDS), 2, "about-to-expire-7", "CN=ABOUT-TO-EXPIRE-7")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(8)).truncatedTo(ChronoUnit.SECONDS), 1, "about-to-expire-8", "CN=ABOUT-TO-EXPIRE-8")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(9)).minus(Duration.ofMinutes(1L)).truncatedTo(ChronoUnit.SECONDS), 0, "about-to-expire-minute", "CN=ABOUT-TO-EXPIRE-MINUTE"))
        );
        assertKeyStoreDocumentContent(keyStoreFile, keyStoreDocument);
    }

    @Test
    public void testInitialKeystoreValidationWithWarningDuration() throws Exception {
        Instant now = Instant.now();

        Map<String, Certificate> certificates = new LinkedHashMap<>();
        certificates.put("expired-day", createTestCertificate("CN=EXPIRED-DAY", now.minus(Period.ofDays(2)), now.minus(Period.ofDays(1))));
        certificates.put("expired-minute", createTestCertificate("CN=EXPIRED-MINUTE", now.minus(Duration.ofMinutes(2L)), now.minus(Duration.ofMinutes(1L))));
        for (int i = 1; i < 6; ++i) {
            certificates.put("about-to-expire-" + i, createTestCertificate("CN=ABOUT-TO-EXPIRE-" + i, now, now.plus(Duration.ofMinutes(i))));
        }
        certificates.put("still-time-minute", createTestCertificate("CN=STILL-TIME-MINUTE", now, now.plus(Duration.ofMinutes(7L))));
        certificates.put("still-time-plenty", createTestCertificate("CN=STILL-TIME-PLENTY", now, now.plus(Period.ofDays(365))));

        File keyStoreFile = createTestKeyStore(certificates);
        String keyStorePath = keyStoreFile.getCanonicalPath();
        Duration minValidationInterval = Duration.ofMinutes(5L);
        Duration maxWarningPeriod = Duration.ofMinutes(6L);

        KeyStoreDocument keyStoreDocument = new KeyStoreDocument(keyStorePath, KEYSTORE_TYPE, KEYSTORE_PASSWORD, minValidationInterval, maxWarningPeriod);

        String expiredTemplate = "Certificate from \"%s\" has already expired (%s) - alias: \"%s\"; subject: \"%s\"";
        String expiringTemplate = "Certificate from \"%s\" expires (%s) in about 0 day(s) - alias: \"%s\"; subject: \"%s\"";
        testLog.verifyLogInOrder(
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS), "expired-day", "CN=EXPIRED-DAY")),
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Duration.ofMinutes(1L)).truncatedTo(ChronoUnit.SECONDS), "expired-minute", "CN=EXPIRED-MINUTE")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Duration.ofMinutes(1L)).truncatedTo(ChronoUnit.SECONDS), "about-to-expire-1", "CN=ABOUT-TO-EXPIRE-1")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Duration.ofMinutes(2L)).truncatedTo(ChronoUnit.SECONDS), "about-to-expire-2", "CN=ABOUT-TO-EXPIRE-2")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Duration.ofMinutes(3L)).truncatedTo(ChronoUnit.SECONDS), "about-to-expire-3", "CN=ABOUT-TO-EXPIRE-3")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Duration.ofMinutes(4L)).truncatedTo(ChronoUnit.SECONDS), "about-to-expire-4", "CN=ABOUT-TO-EXPIRE-4")),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Duration.ofMinutes(5L)).truncatedTo(ChronoUnit.SECONDS), "about-to-expire-5", "CN=ABOUT-TO-EXPIRE-5"))
        );
        assertKeyStoreDocumentContent(keyStoreFile, keyStoreDocument);
    }

    @Test
    public void testOpenStreamTriggersValidationWhenPreviousValidationHasExpired() throws Exception {
        Instant now = Instant.now();

        Map<String, Certificate> certificates = new LinkedHashMap<>();
        certificates.put("expired", createTestCertificate("CN=EXPIRED", now.minus(Period.ofDays(2)), now.minus(Period.ofDays(1))));
        certificates.put("expiring", createTestCertificate("CN=EXPIRING", now, now.plus(Period.ofDays(1))));
        certificates.put("fine", createTestCertificate("CN=FINE", now, now.plus(Period.ofDays(5))));

        File keyStoreFile = createTestKeyStore(certificates);
        String keyStorePath = keyStoreFile.getCanonicalPath();
        Duration minValidationInterval = Duration.ZERO;
        Period maxWarningPeriod = Period.ofDays(2);

        KeyStoreDocument keyStoreDocument = new KeyStoreDocument(keyStorePath, KEYSTORE_TYPE, KEYSTORE_PASSWORD, minValidationInterval, maxWarningPeriod);

        String expiredTemplate = "Certificate from \"%s\" has already expired (%s) - alias: \"expired\"; subject: \"CN=EXPIRED\"";
        String expiringTemplate = "Certificate from \"%s\" expires (%s) in about 1 day(s) - alias: \"expiring\"; subject: \"CN=EXPIRING\"";
        testLog.verifyLogInOrder(
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS))),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS)))
        );

        testLog.reset();
        InputStream stream = keyStoreDocument.openStream();
        stream.close();

        testLog.verifyLogInOrder(
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS))),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS)))
        );
    }

    @Test
    public void testOpenStreamDoesNotTriggerValidationWhenPreviousValidationHasNotExpired() throws Exception {
        Instant now = Instant.now();

        Map<String, Certificate> certificates = new LinkedHashMap<>();
        certificates.put("expired", createTestCertificate("CN=EXPIRED", now.minus(Period.ofDays(2)), now.minus(Period.ofDays(1))));
        certificates.put("expiring", createTestCertificate("CN=EXPIRING", now, now.plus(Period.ofDays(1))));
        certificates.put("fine", createTestCertificate("CN=FINE", now, now.plus(Period.ofDays(5))));

        File keyStoreFile = createTestKeyStore(certificates);
        String keyStorePath = keyStoreFile.getCanonicalPath();
        Duration minValidationInterval = Duration.ofMinutes(10L);
        Period maxWarningPeriod = Period.ofDays(2);

        KeyStoreDocument keyStoreDocument = new KeyStoreDocument(keyStorePath, KEYSTORE_TYPE, KEYSTORE_PASSWORD, minValidationInterval, maxWarningPeriod);

        String expiredTemplate = "Certificate from \"%s\" has already expired (%s) - alias: \"expired\"; subject: \"CN=EXPIRED\"";
        String expiringTemplate = "Certificate from \"%s\" expires (%s) in about 1 day(s) - alias: \"expiring\"; subject: \"CN=EXPIRING\"";
        testLog.verifyLogInOrder(
                Matchers.equalTo(String.format(expiredTemplate, keyStorePath, now.minus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS))),
                Matchers.equalTo(String.format(expiringTemplate, keyStorePath, now.plus(Period.ofDays(1)).truncatedTo(ChronoUnit.SECONDS)))
        );

        testLog.reset();
        InputStream stream = keyStoreDocument.openStream();
        stream.close();

        testLog.verifyLogEmpty();
    }

    private File createTestKeyStore(Map<String, Certificate> certificates) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, KEYSTORE_PASSWORD.toCharArray());
        for (Map.Entry<String, Certificate> entry : certificates.entrySet()) {
            keyStore.setCertificateEntry(entry.getKey(), entry.getValue());
        }
        File keyStoreFile = testFolder.newFile(UUID.randomUUID().toString() + KEYSTORE_EXTENSION);
        try (OutputStream outputStream = new FileOutputStream(keyStoreFile)) {
            keyStore.store(outputStream, KEYSTORE_PASSWORD.toCharArray());
        }
        return keyStoreFile;
    }

    private static X509Certificate createTestCertificate(String subjectDN, Instant notBefore, Instant notAfter) throws Exception {
        AsymmetricCipherKeyPair keyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
        PrivateKey signingKey = TestKeyPairUtil.toPrivateKey((ECPrivateKeyParameters) keyPair.getPrivate());
        PublicKey publicKey = TestKeyPairUtil.toPublicKey((ECPublicKeyParameters) keyPair.getPublic());
        X500Name subjectDnX500Name = new X500Name(subjectDN);

        JcaX509v3CertificateBuilder certificateBuilder = TestCertificateUtil.createX509v3CertificateBuilder(
                null, null, notBefore, notAfter, subjectDnX500Name, publicKey
        );

        ContentSigner signer = TestCertificateUtil.createCertificateSigner(signingKey, "SHA512withECDSA");
        return TestCertificateUtil.toX509Certificate(certificateBuilder.build(signer));
    }

    private static X509Certificate createTestCertificate(String subjectDN, Instant notAfter) throws Exception {
        return createTestCertificate(subjectDN, Instant.now(), notAfter);
    }

    private void assertKeyStoreDocumentContent(File sourceFile, KeyStoreDocument keyStoreDocument) throws Exception {
        byte[] expectedContent = Files.readAllBytes(sourceFile.toPath());

        try (InputStream in = keyStoreDocument.openStream()) {
            byte[] actualContent = IOUtils.toByteArray(in);
            Assert.assertArrayEquals(expectedContent, actualContent);
        }

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            keyStoreDocument.writeTo(out);
            byte[] actualContent = out.toByteArray();
            Assert.assertArrayEquals(expectedContent, actualContent);
        }
    }

}
