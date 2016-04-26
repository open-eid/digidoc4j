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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.testutils.TSLHelper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.tsl.TSLValidationSummary;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;

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
    tslLoader.setCacheExpirationTime(10000L);
    long lastModified = getTslAndReturnCacheModificationTime();
    waitOneSecond();
    long newModificationTime = getTslAndReturnCacheModificationTime();
    assertEquals(lastModified, newModificationTime);
  }

  @Test
  public void loadTsl_whenCacheIsExpired_shouldDownloadNewTsl() throws Exception {
    tslLoader.setCacheExpirationTime(500L);
    long lastModified = getTslAndReturnCacheModificationTime();
    waitOneSecond();
    long newModificationTime = getTslAndReturnCacheModificationTime();
    assertTrue(lastModified < newModificationTime);
  }

  private TslLoader createTslLoader(Configuration configuration) {
    String keystoreLocation = configuration.getTslKeyStoreLocation();
    TslLoader tslLoader = new TslLoader(configuration.getTslLocation(), new File(keystoreLocation), configuration.getTslKeyStorePassword());
    tslLoader.setConnectionTimeout(configuration.getConnectionTimeout());
    tslLoader.setSocketTimeout(configuration.getSocketTimeout());
    tslLoader.setCheckSignature(false);
    return tslLoader;
  }

  private void assertTslValid(TSLRepository tslRepository) {
    List<TSLValidationSummary> summaryList = tslRepository.getSummary();
    for(TSLValidationSummary summary: summaryList) {
      String indication = summary.getIndication();
      String country = summary.getCountry();
      Assert.assertEquals("TSL is not valid for country " + country, "VALID", indication);
    }
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
