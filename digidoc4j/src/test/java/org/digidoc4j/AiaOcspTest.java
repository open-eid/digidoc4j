/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import org.digidoc4j.test.TestAssert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestConstants.DEMO_SK_ESTEID2015_OCSP_CN;
import static org.digidoc4j.test.TestConstants.DEMO_SK_ESTEID2018_OCSP_CN;
import static org.digidoc4j.test.TestConstants.TEST_ESTEID2018_OCSP_CN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesRegex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AiaOcspTest extends AbstractTest {

    @Test
    void signAsiceContainerWithoutAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(false);

        File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        createSignatureBy(container, pkcs12Esteid2018SignatureToken);
        assertContainerIsValid(container);
        assertThat(
                container.getSignatures().get(0).getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN),
                matchesRegex(TEST_ESTEID2018_OCSP_CN)
        );
    }

    @Test
    void signAsiceContainerUsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        assertTrue(configuration.isAiaOcspPreferred());
        File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        createSignatureBy(container, pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals(DEMO_SK_ESTEID2015_OCSP_CN, container.getSignatures().get(0).getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN));
    }

    @Test
    void signAsiceContainerWithEccTokenUsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        assertTrue(configuration.isAiaOcspPreferred());
        File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        createSignatureBy(container, pkcs12EccSignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals(DEMO_SK_ESTEID2015_OCSP_CN, container.getSignatures().get(0).getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN));
    }

    @Test
    void signAsiceContainerWithEsteid2018UsingAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        assertTrue(configuration.isAiaOcspPreferred());
        File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        createSignatureBy(container, pkcs12Esteid2018SignatureToken);
        ContainerValidationResult validationResult = container.validate();
        TestAssert.assertContainerIsValid(validationResult);
        assertHasNoWarnings(validationResult);
        assertEquals(DEMO_SK_ESTEID2018_OCSP_CN, container.getSignatures().get(0).getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN));
    }

    @Test
    void signAsiceContainerWithManuallyConfiguredAiaOcsp() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(false);
        configuration.setOcspSource("http://aia.demo.sk.ee/esteid2015");
        configuration.setUseOcspNonce(false);

        File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        createSignatureBy(container, pkcs12SignatureToken);
        assertTrue(container.validate().isValid());
        assertEquals(DEMO_SK_ESTEID2015_OCSP_CN, container.getSignatures().get(0).getOCSPCertificate().getSubjectName(X509Cert.SubjectName.CN));
    }

    @Test
    @Disabled("Fix by adding AdditionalServiceInformation to TEST of ESTEID-SK 2015 in test TSL")
    void signAsiceContainerWithManuallyConfiguredOlderAiaOcsp_whileUsingOcspNonce_thenOcspRetrievalShouldFail() {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setPreferAiaOcsp(false);
        configuration.setOcspSource("http://aia.demo.sk.ee/esteid2015");

        File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
        Container container = ContainerBuilder.aContainer()
                .withDataFile(testFile1.getPath(), "text/plain")
                .withConfiguration(configuration)
                .build();
        createSignatureBy(container, pkcs12SignatureToken);
        ValidationResult result = container.validate();
        assertFalse(result.isValid());
        assertTrue(result.getErrors().get(0).getMessage().contains("No revocation data for the certificate"));
    }

}
