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
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TslLoaderTest extends AbstractTest {

  private TslLoader tslLoader;

  @Disabled
  @Test
  void loadAndValidateProdTsl() {
    configuration = new Configuration(Configuration.Mode.PROD);
    createTSLLoader();
    tslLoader.prepareTsl();
    TLValidationJob tslValidationJob = tslLoader.getTlValidationJob();
    tslValidationJob.onlineRefresh();
    assertTSLIsValid();
  }

  @Test
  void loadTsl_whenCacheIsNotExpired_shouldUseCachedTsl() {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTslCacheExpirationTime(10000L);
    createTSLLoader();
    long lastModified = refreshTSLAndGetCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    long newModificationTime = refreshTSLAndGetCacheLastModificationTime();
    assertEquals(lastModified, newModificationTime);
  }

  @Test
  void loadTsl_whenCacheIsExpired_shouldDownloadNewTsl() {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTslCacheExpirationTime(500L);
    createTSLLoader();
    long lastModified = refreshTSLAndGetCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    long newModificationTime = refreshTSLAndGetCacheLastModificationTime();
    assertTrue(lastModified < newModificationTime);
  }

  @Test
  @Disabled
  void loadTsl_forAllCountries_byDefault() {
    configuration = new Configuration(Configuration.Mode.PROD);
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertCountryLoaded(tslRepository, "EE");
    assertCountryLoaded(tslRepository, "DK");
    assertCountryLoaded(tslRepository, "ES");
  }

  @Test
  @Disabled
  void loadTsl_forOneCountry() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setTrustedTerritories("EE");
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertCountryLoaded(tslRepository, "EE");
    assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  @Disabled
  void loadTsl_forTwoCountries() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setTrustedTerritories("EE", "ES");
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertCountryLoaded(tslRepository, "EE");
    assertCountryLoaded(tslRepository, "ES");
    assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  void loadTestTsl_shouldContainTestTerritory() {
    configuration = new Configuration(Configuration.Mode.TEST);
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertCountryLoaded(tslRepository, "EE_T");
  }

  /**
   * Ignore countries with invalid TSL: DE (Germany) and HR (Croatia)
   */

  @Test
  @Disabled
  void loadTsl_withoutCountryHr_byDefault() {
    configuration = new Configuration(Configuration.Mode.PROD);
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertCountryLoaded(tslRepository, "EE");
    assertCountryLoaded(tslRepository, "DK");
    assertCountryLoaded(tslRepository, "NO");
    assertCountryNotLoaded(tslRepository, "DE");
    assertCountryNotLoaded(tslRepository, "HR");
  }

  @Test
  void loadProdTsl_withDefaultLotlTruststoreAndPivotSupportDisabled_shouldFail() {
    // TODO: this test might be needed to be updated after the pivot chain is reset
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlPivotSupportEnabled(false);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertEquals(Indication.INDETERMINATE, tslRepository.getValidationCacheInfo().getIndication());
    assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, tslRepository.getValidationCacheInfo().getSubIndication());
    assertEquals(0, configuration.getTSL().getNumberOfCertificates());
  }

  @Test
  void loadProdTsl_withDefaultLotlTruststoreAndPivotSupportEnabled_shouldSucceed() {
    // TODO: this test might be needed to be updated after the pivot chain is reset
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlPivotSupportEnabled(true);
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertEquals(Indication.TOTAL_PASSED, tslRepository.getValidationCacheInfo().getIndication());
    assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
  }

  @Test
  void loadProdTsl_withPivot336LotlTruststoreAndPivotSupportDisabled_shouldSucceed() {
    configuration = new Configuration(Configuration.Mode.PROD);
    // TODO: this might be needed to be updated after the next pivot release
    //  The used truststore contains the certificates specified in pivot LOTL with sequence number 336
    configuration.setLotlTruststorePath("prodFiles/truststores/lotl-pivot336-truststore.p12");
    configuration.setLotlPivotSupportEnabled(false);
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertEquals(Indication.TOTAL_PASSED, tslRepository.getValidationCacheInfo().getIndication());
    assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
  }

  @Test
  void loadProdTsl_withPivot336LotlTruststoreAndPivotSupportEnabled_shouldSucceed() {
    configuration = new Configuration(Configuration.Mode.PROD);
    // TODO: this might be needed to be updated after the next pivot release
    //  The used truststore contains the certificates specified in pivot LOTL with sequence number 336
    configuration.setLotlTruststorePath("prodFiles/truststores/lotl-pivot336-truststore.p12");
    configuration.setLotlPivotSupportEnabled(true);
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertEquals(Indication.TOTAL_PASSED, tslRepository.getValidationCacheInfo().getIndication());
    assertTrue(configuration.getTSL().getNumberOfCertificates() > 0);
  }

  @Test
  void loadProdTsl_withNonLotlSignersTruststoreAndPivotSupportDisabled_shouldFail() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlTruststorePath("testFiles/truststores/lotl-ssl-only-truststore.p12");
    configuration.setLotlPivotSupportEnabled(false);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertEquals(Indication.INDETERMINATE, tslRepository.getValidationCacheInfo().getIndication());
    assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, tslRepository.getValidationCacheInfo().getSubIndication());
    assertEquals(0, configuration.getTSL().getNumberOfCertificates());
  }

  @Test
  void loadProdTsl_withNonLotlSignersTruststoreAndPivotSupportEnabled_shouldFail() {
    configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setLotlTruststorePath("testFiles/truststores/lotl-ssl-only-truststore.p12");
    configuration.setLotlPivotSupportEnabled(true);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    LOTLInfo tslRepository = initTSLAndGetRepository();
    assertEquals(Indication.INDETERMINATE, tslRepository.getValidationCacheInfo().getIndication());
    assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, tslRepository.getValidationCacheInfo().getSubIndication());
    assertEquals(0, configuration.getTSL().getNumberOfCertificates());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    TestTSLUtil.evictCache();
  }

  private void createTSLLoader() {
    tslLoader = new TslLoader(configuration);
  }

  private LOTLInfo initTSLAndGetRepository() {
    createTSLLoader();
    tslLoader.prepareTsl();
    tslLoader.getTlValidationJob().onlineRefresh();
    return tslLoader.getTlValidationJob().getSummary().getLOTLInfos().get(0);
  }

  private long refreshTSLAndGetCacheLastModificationTime() {
    tslLoader.prepareTsl();
    tslLoader.getTlValidationJob().onlineRefresh();
    return TestTSLUtil.getCacheLastModified();
  }

  private void assertTSLIsValid() {
    LOTLInfo lotlInfo = tslLoader.getTlValidationJob().getSummary().getLOTLInfos().get(0);
    for (TLInfo country :lotlInfo.getTLInfos()) {
      Indication indication = country.getValidationCacheInfo().getIndication();
      assertEquals(Indication.TOTAL_PASSED, indication, "TSL is not valid for country " + country);
    }
  }

  private void assertCountryLoaded(LOTLInfo lotlInfo, String countryIsoCode) {
    boolean isLoaded = lotlInfo.getTLInfos().stream()
            .anyMatch(tlInfo -> tlInfo.getParsingCacheInfo().getTerritory().equals(countryIsoCode));
    assertTrue(isLoaded);
  }

  private void assertCountryNotLoaded(LOTLInfo lotlInfo, String countryIsoCode) {
    boolean isLoaded = lotlInfo.getTLInfos().stream()
            .anyMatch(tlInfo -> tlInfo.getParsingCacheInfo().getTerritory().equals(countryIsoCode));
    assertFalse(isLoaded);
  }

}
