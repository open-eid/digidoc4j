package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import org.digidoc4j.Configuration;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

@RunWith(MockitoJUnitRunner.class)
public class CompoundCertificatePoolTest {

    private static final CertificateToken testCertificateToken = new CertificateToken(
            new PKCS12SignatureToken("src/test/resources/testFiles/p12/signout.p12", "test".toCharArray()).getCertificate());

    private CertificatePool trustedCertificatePool;
    @Mock
    private CertificateSource trustedCertificateSource;

    private CompoundCertificatePool compoundCertificatePool;

    @Before
    public void setUpTrustedCertificateSourceAndPool() {
        trustedCertificatePool = new CertificatePool();
        Mockito.doReturn(trustedCertificatePool).when(trustedCertificateSource).getCertificatePool();

        compoundCertificatePool = new CompoundCertificatePool(trustedCertificateSource);
        Mockito.verifyZeroInteractions(trustedCertificateSource);
    }


    @Test
    public void getInstanceShouldNotPoolCertificateIfAlreadyPresentInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        List<CertificateToken> initiallyPooledCertificates = trustedCertificatePool.getCertificateTokens();
        Assert.assertEquals(Collections.singletonList(testCertificateToken), initiallyPooledCertificates);
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));

        CertificateToken response = compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertSame(testCertificateToken, response);

        Assert.assertEquals(initiallyPooledCertificates, trustedCertificatePool.getCertificateTokens());
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(1, trustedCertificatePool.getNumberOfEntities());

        Assert.assertEquals(initiallyPooledCertificates, compoundCertificatePool.getCertificateTokens());
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), compoundCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(1, compoundCertificatePool.getNumberOfEntities());
    }

    @Test
    public void getInstanceShouldPoolCertificateIfPresentInTrustedPoolWithDifferentType() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        List<CertificateToken> initiallyPooledCertificates = trustedCertificatePool.getCertificateTokens();
        Assert.assertEquals(Collections.singletonList(testCertificateToken), initiallyPooledCertificates);
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));

        CertificateToken response = compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertSame(testCertificateToken, response);

        Assert.assertEquals(initiallyPooledCertificates, trustedCertificatePool.getCertificateTokens());
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(1, trustedCertificatePool.getNumberOfEntities());

        Assert.assertEquals(initiallyPooledCertificates, compoundCertificatePool.getCertificateTokens());
        Assert.assertEquals(new HashSet<>(Arrays.asList(CertificateSourceType.TRUSTED_LIST, CertificateSourceType.SIGNATURE)), compoundCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(2, compoundCertificatePool.getNumberOfEntities());
    }

    @Test
    public void getInstanceShouldPoolNewCertificateIfNotPresentInTrustedPool() {
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());

        CertificateToken response = compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertSame(testCertificateToken, response);

        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());

        Assert.assertEquals(Arrays.asList(testCertificateToken), compoundCertificatePool.getCertificateTokens());
        Assert.assertEquals(Collections.singleton(CertificateSourceType.SIGNATURE), compoundCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(1, compoundCertificatePool.getNumberOfEntities());
    }


    @Test
    public void isTrustedShouldReturnTrueIfCertificateTrustedInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertTrue(compoundCertificatePool.isTrusted(testCertificateToken));
    }

    @Test
    public void isTrustedShouldReturnTrueIfCertificateTrustedInCompoundPool() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertTrue(compoundCertificatePool.isTrusted(testCertificateToken));
    }

    @Test
    public void isTrustedShouldReturnTrueIfCertificatePresentInBothButTrustedInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);

        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(new HashSet<>(Arrays.asList(CertificateSourceType.TRUSTED_LIST, CertificateSourceType.SIGNATURE)), compoundCertificatePool.getSources(testCertificateToken));
        Assert.assertTrue(compoundCertificatePool.isTrusted(testCertificateToken));
    }

    @Test
    public void isTrustedShouldReturnTrueIfCertificatePresentInBothButTrustedInCompoundPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);

        Assert.assertEquals(Collections.singleton(CertificateSourceType.SIGNATURE), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(new HashSet<>(Arrays.asList(CertificateSourceType.TRUSTED_LIST, CertificateSourceType.SIGNATURE)), compoundCertificatePool.getSources(testCertificateToken));
        Assert.assertTrue(compoundCertificatePool.isTrusted(testCertificateToken));
    }

    @Test
    public void isTrustedShouldReturnFalseIfCertificateNotTrustedInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertFalse(compoundCertificatePool.isTrusted(testCertificateToken));
    }

    @Test
    public void isTrustedShouldReturnFalseIfCertificateNotTrustedInCompoundPool() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertFalse(compoundCertificatePool.isTrusted(testCertificateToken));
    }

    @Test
    public void isTrustedShouldReturnFalseIfCertificateNotPresentInEitherPool() {
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(0, compoundCertificatePool.getNumberOfCertificates());
        Assert.assertFalse(compoundCertificatePool.isTrusted(testCertificateToken));
    }


    @Test
    public void getSourcesShouldReturnSourceFromTrustedPoolIfCertificatePresentThere() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), compoundCertificatePool.getSources(testCertificateToken));
    }

    @Test
    public void getSourcesShouldReturnSourceFromCompoundPoolIfCertificatePresentThere() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.emptySet(), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(Collections.singleton(CertificateSourceType.SIGNATURE), compoundCertificatePool.getSources(testCertificateToken));
    }

    @Test
    public void getSourcesShouldReturnSourcesFromBothPoolsIfCertificatePresentThere() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singleton(CertificateSourceType.TRUSTED_LIST), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(new HashSet<>(Arrays.asList(CertificateSourceType.TRUSTED_LIST, CertificateSourceType.SIGNATURE)),
                compoundCertificatePool.getSources(testCertificateToken));
    }

    @Test
    public void getSourcesShouldReturnNothingIfCertificateNotPresentAnywhere() {
        Assert.assertEquals(Collections.emptySet(), trustedCertificatePool.getSources(testCertificateToken));
        Assert.assertEquals(Collections.emptySet(), compoundCertificatePool.getSources(testCertificateToken));
    }


    @Test
    public void getIssuersShouldReturnIssuerIfPresentInTrustedPool() {
        trustedCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        List<CertificateToken> issuers = compoundCertificatePool.getIssuers(testCertificateToken);
        Assert.assertEquals(1, issuers.size());
        Assert.assertThat(issuers.get(0).getSubjectX500Principal().getName(), Matchers.containsString("TEST of ESTEID-SK 2015"));
    }

    @Test
    public void getIssuersShouldReturnIssuerIfPresentInCompoundPool() {
        compoundCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        List<CertificateToken> issuers = compoundCertificatePool.getIssuers(testCertificateToken);
        Assert.assertEquals(1, issuers.size());
        Assert.assertThat(issuers.get(0).getSubjectX500Principal().getName(), Matchers.containsString("TEST of ESTEID-SK 2015"));
    }

    @Test
    public void getIssuersShouldReturnEmptyListIfNotPresentInEitherPool() {
        Assert.assertEquals(Collections.emptyList(), compoundCertificatePool.getIssuers(testCertificateToken));
    }


    @Test
    public void getIssuerShouldReturnIssuerIfPresentInTrustedPool() {
        trustedCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        Assert.assertThat(compoundCertificatePool.getIssuer(testCertificateToken).getSubjectX500Principal().getName(),
                Matchers.containsString("TEST of ESTEID-SK 2015"));
    }

    @Test
    public void getIssuerShouldReturnIssuerIfPresentInCompoundPool() {
        compoundCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        Assert.assertThat(compoundCertificatePool.getIssuer(testCertificateToken).getSubjectX500Principal().getName(),
                Matchers.containsString("TEST of ESTEID-SK 2015"));
    }

    @Test
    public void getIssuerShouldReturnNothingIfNotPresentInEitherPool() {
        Assert.assertEquals(null, compoundCertificatePool.getIssuer(testCertificateToken));
    }


    @Test
    public void getTrustAnchorShouldReturnTrustAnchorIfCertificateTrustedInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertEquals(testCertificateToken, trustedCertificatePool.getTrustAnchor(testCertificateToken));
        Assert.assertEquals(testCertificateToken, compoundCertificatePool.getTrustAnchor(testCertificateToken));
    }

    @Test
    @Ignore("Bug in CertificateSource.getTrustAnchor causes infinite loop")
    public void getTrustAnchorShouldReturnTrustAnchorIfEntireChainInTrustedPool() {
        trustedCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertThat(trustedCertificatePool.getTrustAnchor(testCertificateToken).getSubjectX500Principal().getName(), Matchers.containsString("TEST of ESTEID-SK 2015"));
        Assert.assertThat(compoundCertificatePool.getTrustAnchor(testCertificateToken).getSubjectX500Principal().getName(), Matchers.containsString("TEST of ESTEID-SK 2015"));
    }

    @Test
    public void getTrustAnchorShouldReturnTrustAnchorIfCertificateTrustedInCompoundPool() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertNull(trustedCertificatePool.getTrustAnchor(testCertificateToken));
        Assert.assertEquals(testCertificateToken, compoundCertificatePool.getTrustAnchor(testCertificateToken));
    }

    @Test
    @Ignore("Bug in CertificateSource.getTrustAnchor causes infinite loop")
    public void getTrustAnchorShouldReturnTrustAnchorIfEntireChainInCompoundPool() {
        compoundCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertNull(trustedCertificatePool.getTrustAnchor(testCertificateToken));
        Assert.assertEquals(testCertificateToken, compoundCertificatePool.getTrustAnchor(testCertificateToken));
    }

    @Test
    @Ignore("Bug in CertificateSource.getTrustAnchor causes infinite loop")
    public void getTrustAnchorShouldReturnTrustAnchorIfTrustAnchorInTrustedPoolAndCertificateInCompoundPool() {
        trustedCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertNull(trustedCertificatePool.getTrustAnchor(testCertificateToken));
        Assert.assertEquals(testCertificateToken, compoundCertificatePool.getTrustAnchor(testCertificateToken));
    }


    @Test
    public void getByX500PrincipalShouldReturnCertificateIfPresentInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertEquals(Collections.singleton(testCertificateToken), compoundCertificatePool.get(testCertificateToken.getSubjectX500Principal()));
    }

    @Test
    public void getByX500PrincipalShouldReturnCertificateIfPresentInCompoundPool() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singleton(testCertificateToken), compoundCertificatePool.get(testCertificateToken.getSubjectX500Principal()));
    }

    @Test
    public void getByX500PrincipalShouldReturnCertificateIfPresentInBothPools() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singleton(testCertificateToken), compoundCertificatePool.get(testCertificateToken.getSubjectX500Principal()));
    }

    @Test
    public void getByX500PrincipalShouldReturnEmptySetIfNotPresentInEitherPools() {
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(0, compoundCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(Collections.emptySet(), compoundCertificatePool.get(testCertificateToken.getSubjectX500Principal()));
    }


    @Test
    public void getByPublicKeyShouldReturnCertificateIfPresentInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertEquals(Collections.singletonList(testCertificateToken), compoundCertificatePool.get(testCertificateToken.getPublicKey()));
    }

    @Test
    public void getByPublicKeyShouldReturnCertificateIfPresentInCompoundPool() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singletonList(testCertificateToken), compoundCertificatePool.get(testCertificateToken.getPublicKey()));
    }

    @Test
    public void getByPublicKeyShouldReturnCertificateIfPresentInBothPools() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singletonList(testCertificateToken), compoundCertificatePool.get(testCertificateToken.getPublicKey()));
    }

    @Test
    public void getByPublicKeyShouldReturnEmptySetIfNotPresentInEitherPools() {
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(0, compoundCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(Collections.emptyList(), compoundCertificatePool.get(testCertificateToken.getPublicKey()));
    }


    @Test
    public void getBySkiShouldReturnCertificateIfPresentInTrustedPool() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        Assert.assertEquals(Collections.singletonList(testCertificateToken), compoundCertificatePool.getBySki(DSSASN1Utils.computeSkiFromCert(testCertificateToken)));
    }

    @Test
    public void getBySkiShouldReturnCertificateIfPresentInCompoundPool() {
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singletonList(testCertificateToken), compoundCertificatePool.getBySki(DSSASN1Utils.computeSkiFromCert(testCertificateToken)));
    }

    @Test
    public void getBySkiShouldReturnCertificateIfPresentInBothPools() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        Assert.assertEquals(Collections.singletonList(testCertificateToken), compoundCertificatePool.getBySki(DSSASN1Utils.computeSkiFromCert(testCertificateToken)));
    }

    @Test
    public void getBySkiShouldReturnEmptySetIfNotPresentInEitherPools() {
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(0, compoundCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(Collections.emptyList(), compoundCertificatePool.getBySki(DSSASN1Utils.computeSkiFromCert(testCertificateToken)));
    }


    @Test
    public void importCertsShouldNotAddCertsIfAlreadyPresentInTrustedPool() {
        Configuration configuration = Configuration.of(Configuration.Mode.TEST);
        Assert.assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);

        trustedCertificatePool.importCerts(configuration.getTSL());
        List<CertificateToken> initialTrustedCertificates = trustedCertificatePool.getCertificateTokens();
        Assert.assertEquals(configuration.getTSL().getNumberOfCertificates(), initialTrustedCertificates.size());

        compoundCertificatePool.importCerts(configuration.getTSL());
        Assert.assertEquals(initialTrustedCertificates, trustedCertificatePool.getCertificateTokens());
        Assert.assertEquals(initialTrustedCertificates, compoundCertificatePool.getCertificateTokens());
        Assert.assertEquals(trustedCertificatePool.getNumberOfEntities(), compoundCertificatePool.getNumberOfEntities());
    }

    @Test
    public void importCertsShouldAddCertsIfNotPresentInTrustedPool() {
        Configuration configuration = Configuration.of(Configuration.Mode.TEST);
        Assert.assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());

        compoundCertificatePool.importCerts(configuration.getTSL());
        Assert.assertEquals(0, trustedCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(configuration.getTSL().getNumberOfCertificates(), compoundCertificatePool.getNumberOfCertificates());
    }

    @Test
    public void importCertsShouldAddMissingCertsIfSomePresentInTrustedPool() {
        Configuration configuration = Configuration.of(Configuration.Mode.TEST);
        int initialTslCertCount = configuration.getTSL().getNumberOfCertificates();
        Assert.assertTrue(initialTslCertCount > 0);

        trustedCertificatePool.importCerts(configuration.getTSL());
        List<CertificateToken> initialTrustedCertificates = trustedCertificatePool.getCertificateTokens();
        Assert.assertEquals(initialTslCertCount, initialTrustedCertificates.size());

        configuration.getTSL().addTSLCertificate(testCertificateToken.getCertificate());
        Assert.assertEquals(initialTslCertCount + 1, configuration.getTSL().getNumberOfCertificates());

        compoundCertificatePool.importCerts(configuration.getTSL());
        Assert.assertEquals(initialTrustedCertificates, trustedCertificatePool.getCertificateTokens());
        Assert.assertEquals(initialTslCertCount + 1, compoundCertificatePool.getNumberOfCertificates());
        Assert.assertEquals(0, trustedCertificatePool.get(testCertificateToken.getPublicKey()).size());
        Assert.assertTrue(compoundCertificatePool.get(testCertificateToken.getPublicKey()).size() > 0);
    }


    @Test
    public void getCertificateTokensShouldPreserveCertificatesOrder() {
        trustedCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());
        List<CertificateToken> trustedCertsList = trustedCertificatePool.getCertificateTokens();
        Assert.assertTrue(trustedCertsList.size() > 0);

        compoundCertificatePool.getInstance(testCertificateToken, CertificateSourceType.SIGNATURE);
        List<CertificateToken> compoundCertsList = compoundCertificatePool.getCertificateTokens();
        Assert.assertEquals(trustedCertsList.size() + 1, compoundCertsList.size());
        Assert.assertEquals(trustedCertsList, compoundCertsList.subList(0, trustedCertsList.size()));
        Assert.assertEquals(testCertificateToken, compoundCertsList.get(trustedCertsList.size()));
    }

    @Test
    public void getCertificateTokensShouldPreserveCertificatesOrder2() {
        trustedCertificatePool.getInstance(testCertificateToken, CertificateSourceType.TRUSTED_LIST);
        compoundCertificatePool.importCerts(Configuration.of(Configuration.Mode.TEST).getTSL());

        Assert.assertTrue(compoundCertificatePool.getNumberOfCertificates() > 1);
        Assert.assertEquals(testCertificateToken, compoundCertificatePool.getCertificateTokens().get(0));
    }

}