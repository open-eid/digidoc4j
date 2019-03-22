package org.digidoc4j;

import org.junit.Ignore;
import org.junit.Test;
import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AiaOcspTest extends AbstractTest {

    @Test
    public void signAsiceContainerWithoutAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        assertFalse(configuration.isAiaOcspPreferred());

        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, this.pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("EMAILADDRESS=pki@sk.ee, CN=TEST of SK OCSP RESPONDER 2011, OU=OCSP, O=AS Sertifitseerimiskeskus, C=EE", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    public void signAsiceContainerUsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(true);
        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, this.pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of ESTEID-SK 2015 AIA OCSP RESPONDER 2018", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    public void bdocContainerIgnoresAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(true);
        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("EMAILADDRESS=pki@sk.ee, CN=TEST of SK OCSP RESPONDER 2011, OU=OCSP, O=AS Sertifitseerimiskeskus, C=EE", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    public void signAsiceContainerWithEccTokenUsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(true);
        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, this.pkcs12EccSignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of ESTEID-SK 2011 AIA OCSP RESPONDER 2018", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    @Ignore("Fix by adding AdditionalServiceInformation to TEST of ESTEID2018 in test TSL")
    public void signAsiceContainerWithEsteid2018UsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(true);
        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, this.pkcs12Esteid2018SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of ESTEID-SK 2018 AIA OCSP RESPONDER 2018", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    public void signAsiceContainerWithManuallyConfiguredAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        assertFalse(configuration.isAiaOcspPreferred());
        configuration.setOcspSource("http://aia.demo.sk.ee/esteid2015");
        configuration.setUseOcspNonce(false);

        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, this.pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of ESTEID-SK 2015 AIA OCSP RESPONDER 2018", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    @Ignore("Fix by adding AdditionalServiceInformation to TEST of ESTEID-SK 2015 in test TSL")
    public void signAsiceContainerWithManuallyConfiguredOlderAiaOcsp_whileUsingOcspNonce_thenOcspRetrievalShouldFail() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        assertFalse(configuration.isAiaOcspPreferred());
        configuration.setOcspSource("http://aia.demo.sk.ee/esteid2015");

        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, this.pkcs12SignatureToken);
        ValidationResult result = container.validate();
        assertFalse(result.isValid());
        assertTrue(result.getErrors().get(0).getMessage().contains("No revocation data for the certificate"));
    }

}
