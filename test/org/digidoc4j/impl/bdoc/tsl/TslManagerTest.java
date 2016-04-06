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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.digidoc4j.Configuration;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.testutils.TSLHelper;
import org.junit.Before;
import org.junit.Test;

public class TslManagerTest {

  private Configuration configuration;
  private TslManager tslManager;

  @Before
  public void setUp() throws Exception {
    configuration = new Configuration(Configuration.Mode.TEST);
    tslManager = new TslManager(configuration);
    deleteTSLCache();
  }

  @Test
  public void getNewTsl() throws Exception {
    TSLCertificateSource tsl = tslManager.getTsl();
    assertNotNull(tsl);
  }

  @Test
  public void getCachedTsl() throws Exception {
    TSLCertificateSource tsl = tslManager.getTsl();
    TSLCertificateSource newTsl = tslManager.getTsl();
    assertSame(tsl, newTsl);
  }

  @Test
  public void getLazilyInitializedTsl() throws Exception {
    TSLCertificateSource tsl = tslManager.getTsl();
    assertTrue(tsl instanceof LazyTslCertificateSource);
    assertFalse(((LazyTslCertificateSource)tsl).getLastCacheReloadingTime() != null);
    assertTrue(tsl.getCertificatePool().getNumberOfCertificates() > 0);
    assertTrue(((LazyTslCertificateSource)tsl).getLastCacheReloadingTime() != null);
  }

  @Test
  public void getTslwithCacheExpirationTime() throws Exception {
    configuration.setTslCacheExpirationTime(1337);
    LazyTslCertificateSource tsl = (LazyTslCertificateSource)tslManager.getTsl();
    assertNotNull(tsl.getCacheExpirationTime());
    assertEquals(1337, tsl.getCacheExpirationTime().longValue());
  }

  private void deleteTSLCache() {
    TSLHelper.deleteTSLCache();
  }
}
