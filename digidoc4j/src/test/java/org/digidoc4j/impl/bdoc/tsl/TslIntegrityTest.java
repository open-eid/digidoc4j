/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.tsl;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.DetachedXadesSignatureBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

public class TslIntegrityTest extends AbstractTest {

    private Configuration configuration;

    private int initialCertificatesCountInTslSource;
    private int initialCertificatesCountInTslPool;
    private int initialEntitiesCountInTslPool;

    @Before
    public void setUpCentralConfiguration() {
        configuration = Configuration.of(Configuration.Mode.TEST);
        configuration.getTSL().refresh();

        initialCertificatesCountInTslSource = configuration.getTSL().getNumberOfCertificates();
        initialCertificatesCountInTslPool = configuration.getTSL().getNumberOfCertificates();
        initialEntitiesCountInTslPool = configuration.getTSL().getNumberOfTrustedEntityKeys();
        Assert.assertEquals(initialCertificatesCountInTslSource, initialCertificatesCountInTslPool);
    }

    @Test
    public void centralTslShouldNotChangeAfterSignatureCreationNorValidation() {
        Signature signature = DetachedXadesSignatureBuilder.withConfiguration(configuration)
                .withSignatureToken(pkcs12SignatureToken)
                .withDataFile(createDefaultDataFile())
                .withSignatureId("SIG-ID")
                .invokeSigning();

        assertCentralTslNotChanged(pkcs12SignatureToken.getCertificate());
        Assert.assertNotNull(signature.validateSignature());
        assertCentralTslNotChanged(pkcs12SignatureToken.getCertificate());
    }

    @Test
    public void centralTslShouldNotChangeAfterSigningOrValidatingContainer() {
        Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICE)
                .withDataFile(createDefaultDataFile())
                .withConfiguration(configuration)
                .build();

        Signature signature = SignatureBuilder.aSignature(container)
                .withSignatureToken(pkcs12SignatureToken)
                .withSignatureId("SIG-ID")
                .invokeSigning();

        assertCentralTslNotChanged(pkcs12SignatureToken.getCertificate());
        Assert.assertNotNull(signature.validateSignature());
        assertCentralTslNotChanged(pkcs12SignatureToken.getCertificate());

        container.addSignature(signature);
        assertCentralTslNotChanged(pkcs12SignatureToken.getCertificate());
        Assert.assertNotNull(container.validate());
        assertCentralTslNotChanged(pkcs12SignatureToken.getCertificate());
    }

    private void assertCentralTslNotChanged(X509Certificate certificateExpectedToBeMissing) {
        assertCentralTslCertificateSourceNotChanged(certificateExpectedToBeMissing);
        assertCentralTslCertificatePoolNotChanged(certificateExpectedToBeMissing);
    }

    private void assertCentralTslCertificateSourceNotChanged(X509Certificate certificateExpectedToBeMissing) {
        Assert.assertEquals(
                String.format("TSL certificate source is expected to contain %d certificates", initialCertificatesCountInTslSource),
                initialCertificatesCountInTslSource,
                configuration.getTSL().getNumberOfCertificates()
        );
        Assert.assertFalse(
                String.format("TSL certificate source is expected not to contain certificate %s", certificateExpectedToBeMissing.getSubjectDN().getName()),
                configuration.getTSL().getCertificates().stream().anyMatch(ct -> certificateExpectedToBeMissing.equals(ct.getCertificate()))
        );
    }

    private void assertCentralTslCertificatePoolNotChanged(X509Certificate certificateExpectedToBeMissing) {
        Assert.assertEquals(
                String.format("TSL certificate pool is expected to contain %d certificates", initialCertificatesCountInTslPool),
                initialCertificatesCountInTslPool,
                configuration.getTSL().getNumberOfCertificates()
        );
        Assert.assertEquals(
                String.format("TSL certificate pool is expected to contain %d entities", initialEntitiesCountInTslPool),
                initialEntitiesCountInTslPool,
                configuration.getTSL().getNumberOfTrustedEntityKeys()
        );
        Assert.assertFalse(
                String.format("TSL certificate pool is expected not to contain certificate %s", certificateExpectedToBeMissing.getSubjectDN().getName()),
                configuration.getTSL().getCertificates().stream().anyMatch(ct -> certificateExpectedToBeMissing.equals(ct.getCertificate()))
        );
    }

    private static DataFile createDefaultDataFile() {
        return new DataFile(new byte[] {0, 1, 2, 3}, "filename", "application/octet-stream");
    }

}
