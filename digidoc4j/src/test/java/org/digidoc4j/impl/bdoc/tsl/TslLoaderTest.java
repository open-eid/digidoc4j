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

import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.tsl.TslLoader;
import org.digidoc4j.test.util.TestCommonUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Map;

public class TslLoaderTest extends AbstractTest {

  private TslLoader tslLoader;

  @Ignore // TODO: DD4J-410
  @Test
  public void loadAndValidateProdTsl() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.createTSLLoader();
    this.tslLoader.setCheckSignature(true);
    this.tslLoader.prepareTsl();
    TSLValidationJob tslValidationJob = this.tslLoader.getTslValidationJob();
    tslValidationJob.refresh();
    this.tslLoader.getTslRepository();
    this.assertTSLIsValid();
  }

  @Test
  public void loadTsl_whenCacheIsNotExpired_shouldUseCachedTsl() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTslCacheExpirationTime(10000L);
    this.createTSLLoader();
    long lastModified = this.refreshTSLAndGetCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    long newModificationTime = this.refreshTSLAndGetCacheLastModificationTime();
    Assert.assertEquals(lastModified, newModificationTime);
  }

  @Test
  public void loadTsl_whenCacheIsExpired_shouldDownloadNewTsl() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTslCacheExpirationTime(500L);
    this.createTSLLoader();
    long lastModified = this.refreshTSLAndGetCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    long newModificationTime = this.refreshTSLAndGetCacheLastModificationTime();
    Assert.assertTrue(lastModified < newModificationTime);
  }

  @Ignore // TODO: DD4J-410
  @Test
  public void loadTsl_forAllCountries_byDefault() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.configuration = new Configuration(Configuration.Mode.PROD);
    TSLRepository tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryLoaded(tslRepository, "DK");
    this.assertCountryLoaded(tslRepository, "ES");
  }

  @Ignore // TODO: DD4J-410
  @Test
  public void loadTsl_forOneContry() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setTrustedTerritories("EE");
    TSLRepository tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryNotLoaded(tslRepository, "FR");
  }

  @Ignore // TODO: DD4J-410
  @Test
  public void loadTsl_forTwoCountries() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.PROD);
    this.configuration.setTrustedTerritories("EE", "ES");
    TSLRepository tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryLoaded(tslRepository, "ES");
    this.assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  public void loadTestTsl_shouldContainTestTerritory() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    TSLRepository tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE_T");
  }

  /**
   * Ignore countries with invalid TSL: DE (Germany) and HR (Croatia)
   */

  @Ignore // TODO: DD4J-410
  @Test
  public void loadTsl_withoutCountryHr_byDefault() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.configuration = new Configuration(Configuration.Mode.PROD);
    TSLRepository tslRepository = this.initTSLAndGetRepository();
    this.assertCountryLoaded(tslRepository, "EE");
    this.assertCountryLoaded(tslRepository, "DK");
    this.assertCountryLoaded(tslRepository, "NO");
    this.assertCountryNotLoaded(tslRepository, "DE");
    this.assertCountryNotLoaded(tslRepository, "HR");
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
    this.tslLoader.setCheckSignature(false);
  }

  private TSLRepository initTSLAndGetRepository() {
    this.createTSLLoader();
    this.tslLoader.prepareTsl();
    this.tslLoader.getTslValidationJob().refresh();
    return this.tslLoader.getTslRepository();
  }

  private long refreshTSLAndGetCacheLastModificationTime() {
    this.tslLoader.prepareTsl();
    this.tslLoader.getTslValidationJob().refresh();
    return TestTSLUtil.getCacheLastModified();
  }

  private void assertTSLIsValid() {
    TSLRepository repository = this.tslLoader.getTslRepository();
    Map<String, TSLValidationModel> modelMap = repository.getAllMapTSLValidationModels();
    for (String country : modelMap.keySet()) {
      TSLValidationModel model = repository.getByCountry(country);
      Indication indication = model.getValidationResult().getIndication();
      Assert.assertEquals("TSL is not valid for country " + country, Indication.TOTAL_PASSED, indication);
    }
  }

  private void assertCountryLoaded(TSLRepository tslRepository, String countryIsoCode) {
    TSLValidationModel model = tslRepository.getByCountry(countryIsoCode);
    Assert.assertNotNull(String.format("TSL model for country <%s> is null", countryIsoCode), model);
    Assert.assertTrue(model.getParseResult().getServiceProviders().size() > 0);
  }

  private void assertCountryNotLoaded(TSLRepository tslRepository, String countryIsoCode) {
    TSLValidationModel countryTsl = tslRepository.getByCountry(countryIsoCode);
    Assert.assertNull(countryTsl);
  }

}
