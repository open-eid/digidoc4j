package org.digidoc4j;

import org.digidoc4j.test.TestAssert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;

import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesRegex;
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
        this.createSignatureBy(container, pkcs12SignatureToken);
        assertContainerIsValid(container);
        assertThat(
                container.getSignatures().get(0).getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN),
                matchesRegex("TEST of ESTEID-SK 2015 AIA OCSP RESPONDER 202[3-9][0-1][0-9]")
        );
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
        this.createSignatureBy(container, pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of ESTEID-SK 2015 AIA OCSP RESPONDER 2018", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
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
        this.createSignatureBy(container, pkcs12EccSignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals("C=EE, O=SK ID Solutions AS, OU=OCSP, CN=DEMO of ESTEID-SK 2015 AIA OCSP RESPONDER 2018", container.getSignatures().get(0).getOCSPCertificate().getSubjectName());
    }

    @Test
    public void signAsiceContainerWithEsteid2018UsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(true);
        File testFile1 = this.createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        this.createSignatureBy(container, pkcs12Esteid2018SignatureToken);
        ContainerValidationResult validationResult = container.validate();
        TestAssert.assertContainerIsValid(validationResult);
        assertHasNoWarnings(validationResult);
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
        this.createSignatureBy(container, pkcs12SignatureToken);
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
        this.createSignatureBy(container, pkcs12SignatureToken);
        ValidationResult result = container.validate();
        assertFalse(result.isValid());
        assertTrue(result.getErrors().get(0).getMessage().contains("No revocation data for the certificate"));
    }

}
