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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.tsl.TslLoader;
import org.digidoc4j.test.MockTSLRefreshCallback;
import org.digidoc4j.test.util.TestCommonUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class TslLoaderTest extends AbstractTest {

  private TslLoader tslLoader;

  @Ignore
  @Test
  public void loadAndValidateProdTsl() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.createTSLLoader();
    this.tslLoader.prepareTsl();
    TLValidationJob tslValidationJob = this.tslLoader.getTlValidationJob();
    tslValidationJob.onlineRefresh();
    this.assertTSLIsValid();
  }

  @Test
  public void loadTsl_whenCacheIsNotExpired_shouldUseCachedTsl() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTslCacheExpirationTime(10000L);
    this.createTSLLoader();
    long lastModified = this.refreshTSLAndGetCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    long newModificationTime = this.refreshTSLAndGetCacheLastModificationTime();
    Assert.assertEquals(lastModified, newModificationTime);
  }

  @Test
  public void loadTsl_whenCacheIsExpired_shouldDownloadNewTsl() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTslCacheExpirationTime(500L);
    this.createTSLLoader();
    long lastModified = this.refreshTSLAndGetCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    long newModificationTime = this.refreshTSLAndGetCacheLastModificationTime();
    Assert.assertTrue(lastModified < newModificationTime);
  }

  @Test
  @Ignore
  public void loadTsl_forAllCountries_byDefault() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryLoaded(tslRepository, "DK");
    this.assertCountryLoaded(tslRepository, "ES");
  }

  @Test
  @Ignore
  public void loadTsl_forOneCountry() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setTrustedTerritories("EE");
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  @Ignore
  public void loadTsl_forTwoCountries() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setTrustedTerritories("EE", "ES");
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryLoaded(tslRepository, "ES");
    this.assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  public void loadTestTsl_shouldContainTestTerritory() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE_T");
  }

  /**
   * Ignore countries with invalid TSL: DE (Germany) and HR (Croatia)
   */

  @Test
  @Ignore
  public void loadTsl_withoutCountryHr_byDefault() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryLoaded(tslRepository, "DK");
    this.assertCountryLoaded(tslRepository, "NO");
    this.assertCountryNotLoaded(tslRepository, "DE");
    this.assertCountryNotLoaded(tslRepository, "HR");
  }

  @Test
  public void loadProdTsl_withDefaultLotlTruststoreAndPivotSupportDisabled_shouldFail() {
    // TODO: this test might be needed to be updated after the pivot chain is reset
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlPivotSupportEnabled(false);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    Assert.assertEquals(Indication.INDETERMINATE, tslRepository.getValidationCacheInfo().getIndication());
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, tslRepository.getValidationCacheInfo().getSubIndication());
    Assert.assertEquals(0, configuration.getTSL().getNumberOfCertificates());
  }

  @Test
  public void loadProdTsl_withDefaultLotlTruststoreAndPivotSupportEnabled_shouldSucceed() {
    // TODO: this test might be needed to be updated after the pivot chain is reset
    this.configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlPivotSupportEnabled(true);
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    Assert.assertEquals(Indication.TOTAL_PASSED, tslRepository.getValidationCacheInfo().getIndication());
    Assert.assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
  }

  @Test
  public void loadProdTsl_withPivot336LotlTruststoreAndPivotSupportDisabled_shouldSucceed() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    // TODO: this might be needed to be updated after the next pivot release
    //  The used truststore contains the certificates specified in pivot LOTL with sequence number 336
    configuration.setLotlTruststorePath("prodFiles/truststores/lotl-pivot336-truststore.p12");
    configuration.setLotlPivotSupportEnabled(false);
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    Assert.assertEquals(Indication.TOTAL_PASSED, tslRepository.getValidationCacheInfo().getIndication());
    Assert.assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
  }

  @Test
  public void loadProdTsl_withPivot336LotlTruststoreAndPivotSupportEnabled_shouldSucceed() {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    // TODO: this might be needed to be updated after the next pivot release
    //  The used truststore contains the certificates specified in pivot LOTL with sequence number 336
    configuration.setLotlTruststorePath("prodFiles/truststores/lotl-pivot336-truststore.p12");
    configuration.setLotlPivotSupportEnabled(true);
    LOTLInfo tslRepository = this.initTSLAndGetRepository();
    Assert.assertEquals(Indication.TOTAL_PASSED, tslRepository.getValidationCacheInfo().getIndication());
    Assert.assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
  }

  @Test
  public void loadProdTsl_withNonLotlSignersTruststoreAndPivotSupportDisabled_shouldFail() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlTruststorePath("testFiles/truststores/lotl-ssl-only-truststore.p12");
    configuration.setLotlPivotSupportEnabled(false);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    LOTLInfo tslRepository = initTSLAndGetRepository();
    Assert.assertEquals(Indication.INDETERMINATE, tslRepository.getValidationCacheInfo().getIndication());
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, tslRepository.getValidationCacheInfo().getSubIndication());
    Assert.assertEquals(0, configuration.getTSL().getNumberOfCertificates());
  }

  @Test
  public void loadProdTsl_withNonLotlSignersTruststoreAndPivotSupportEnabled_shouldFail() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlTruststorePath("testFiles/truststores/lotl-ssl-only-truststore.p12");
    configuration.setLotlPivotSupportEnabled(true);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    LOTLInfo tslRepository = initTSLAndGetRepository();
    Assert.assertEquals(Indication.INDETERMINATE, tslRepository.getValidationCacheInfo().getIndication());
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, tslRepository.getValidationCacheInfo().getSubIndication());
    Assert.assertEquals(0, configuration.getTSL().getNumberOfCertificates());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    TestTSLUtil.evictCache();
  }

  private void createTSLLoader() {
    this.tslLoader = new TslLoader(this.configuration);
  }

  private LOTLInfo initTSLAndGetRepository() {
    this.createTSLLoader();
    this.tslLoader.prepareTsl();
    this.tslLoader.getTlValidationJob().onlineRefresh();
    return this.tslLoader.getTlValidationJob().getSummary().getLOTLInfos().get(0);
  }

  private long refreshTSLAndGetCacheLastModificationTime() {
    this.tslLoader.prepareTsl();
    this.tslLoader.getTlValidationJob().onlineRefresh();
    return TestTSLUtil.getCacheLastModified();
  }

  private void assertTSLIsValid() {
    LOTLInfo lotlInfo = this.tslLoader.getTlValidationJob().getSummary().getLOTLInfos().get(0);
    for (TLInfo country :lotlInfo.getTLInfos()) {
      Indication indication = country.getValidationCacheInfo().getIndication();
      Assert.assertEquals("TSL is not valid for country " + country, Indication.TOTAL_PASSED, indication);
    }
  }

  private void assertCountryLoaded(LOTLInfo lotlInfo, String countryIsoCode) {
    boolean isLoaded = lotlInfo.getTLInfos().stream()
            .anyMatch(tlInfo -> tlInfo.getParsingCacheInfo().getTerritory().equals(countryIsoCode));
    Assert.assertTrue(isLoaded);
  }

  private void assertCountryNotLoaded(LOTLInfo lotlInfo, String countryIsoCode) {
    boolean isLoaded = lotlInfo.getTLInfos().stream()
            .anyMatch(tlInfo -> tlInfo.getParsingCacheInfo().getTerritory().equals(countryIsoCode));
    Assert.assertFalse(isLoaded);
  }

}
