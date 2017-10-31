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

import static org.digidoc4j.Configuration.Mode.TEST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.digidoc4j.Configuration;
import org.digidoc4j.testutils.TSLHelper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.policy.rules.Indication;

public class TslLoaderTest {

  private Configuration configuration;
  private TslLoader tslLoader;

  @Before
  public void setUp() throws Exception {
    configuration = new Configuration(TEST);
    tslLoader = createTslLoader(configuration);
    TslLoader.invalidateCache();
  }

  @Test
  @Ignore("TODO: Wait till problem with RO is solved")
  public void loadAndValidateProdTsl() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    TslLoader tslLoader = createTslLoader(configuration);
    tslLoader.setCheckSignature(true);
    tslLoader.prepareTsl();
    TSLValidationJob tslValidationJob = tslLoader.getTslValidationJob();
    tslValidationJob.refresh();
    TSLRepository tslRepository = tslLoader.getTslRepository();
    assertTslValid(tslRepository);
  }

  @Test
  public void loadTsl_whenCacheIsNotExpired_shouldUseCachedTsl() throws Exception {
    configuration.setTslCacheExpirationTime(10000L);
    tslLoader = createTslLoader(configuration);
    long lastModified = getTslAndReturnCacheModificationTime();
    waitOneSecond();
    long newModificationTime = getTslAndReturnCacheModificationTime();
    assertEquals(lastModified, newModificationTime);
  }

  @Test
  public void loadTsl_whenCacheIsExpired_shouldDownloadNewTsl() throws Exception {
    configuration.setTslCacheExpirationTime(500L);
    tslLoader = createTslLoader(configuration);
    long lastModified = getTslAndReturnCacheModificationTime();
    waitOneSecond();
    long newModificationTime = getTslAndReturnCacheModificationTime();
    assertTrue(lastModified < newModificationTime);
  }

  @Test
  public void loadTsl_forAllCountries_byDefault() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    TSLRepository tslRepository = loadTsl(configuration);
    assertCountryLoaded(tslRepository, "EE");
    assertCountryLoaded(tslRepository, "FR");
    assertCountryLoaded(tslRepository, "ES");
  }

  @Test
  public void loadTsl_forOneContry() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setTrustedTerritories("EE");
    TSLRepository tslRepository = loadTsl(configuration);
    assertCountryLoaded(tslRepository, "EE");
    assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  public void loadTsl_forTwoCountries() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    configuration.setTrustedTerritories("EE", "ES");
    TSLRepository tslRepository = loadTsl(configuration);
    assertCountryLoaded(tslRepository, "EE");
    assertCountryLoaded(tslRepository, "ES");
    assertCountryNotLoaded(tslRepository, "FR");
  }

  @Test
  public void loadTestTsl_shouldContainTestTerritory() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    TSLRepository tslRepository = loadTsl(configuration);
    assertCountryLoaded(tslRepository, "EE_T");
  }

  /**
   * Ignore countries with invalid TSL: DE (Germany) and HR (Croatia)
   */
  @Test
  public void loadTsl_withoutCountryHr_byDefault() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.PROD);
    TSLRepository tslRepository = loadTsl(configuration);
    assertCountryLoaded(tslRepository, "EE");
    assertCountryLoaded(tslRepository, "FR");
    assertCountryLoaded(tslRepository, "NO");
    assertCountryNotLoaded(tslRepository, "DE");
    assertCountryNotLoaded(tslRepository, "HR");
  }

  private TslLoader createTslLoader(Configuration configuration) {
    TslLoader tslLoader = new TslLoader(configuration);
    tslLoader.setCheckSignature(false);
    return tslLoader;
  }

  private TSLRepository loadTsl(Configuration configuration) {
    TslLoader tslLoader = createTslLoader(configuration);
    tslLoader.prepareTsl();
    TSLValidationJob tslValidationJob = tslLoader.getTslValidationJob();
    tslValidationJob.refresh();
    return tslLoader.getTslRepository();
  }

  private void assertTslValid(TSLRepository tslRepository) {
    Map<String, TSLValidationModel> modelMap = tslRepository.getAllMapTSLValidationModels();
    for (String country : modelMap.keySet()) {
      TSLValidationModel model = tslRepository.getByCountry(country);
      Indication indication = model.getValidationResult().getIndication();
      Assert.assertEquals("TSL is not valid for country " + country, Indication.TOTAL_PASSED, indication);
    }
  }

  private void assertCountryLoaded(TSLRepository tslRepository, String countryIsoCode) {
    TSLValidationModel countryTsl = tslRepository.getByCountry(countryIsoCode);
    assertNotNull(countryTsl);
    assertTrue(countryTsl.getParseResult().getServiceProviders().size() > 0);
  }

  private void assertCountryNotLoaded(TSLRepository tslRepository, String countryIsoCode) {
    TSLValidationModel countryTsl = tslRepository.getByCountry(countryIsoCode);
    assertNull(countryTsl);
  }

  private long getTslAndReturnCacheModificationTime() {
    tslLoader.prepareTsl();
    tslLoader.getTslValidationJob().refresh();
    return TSLHelper.getCacheLastModificationTime();
  }

  private void waitOneSecond() throws InterruptedException {
    Thread.sleep(1000L); //Waiting is necessary to check changes in the cached files modification time
  }
}
