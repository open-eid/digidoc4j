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
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.impl.asic.tsl.LazyTslCertificateSource;
import org.digidoc4j.impl.asic.tsl.TslManager;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TslManagerTest extends AbstractTest {

  private TslManager tslManager;

  @Test
  public void getNewTsl() {
    TSLCertificateSource tsl = tslManager.getTsl();
    assertNotNull(tsl);
  }

  @Test
  public void getCachedTsl() {
    TSLCertificateSource tsl = tslManager.getTsl();
    TSLCertificateSource newTsl = tslManager.getTsl();
    assertSame(tsl, newTsl);
  }

  @Test
  public void getLazilyInitializedTsl() {
    TSLCertificateSource tsl = tslManager.getTsl();
    assertInstanceOf(LazyTslCertificateSource.class, tsl);
    assertNull(((LazyTslCertificateSource) tsl).getLastCacheReloadingTime());
    assertTrue(tsl.getNumberOfCertificates() > 0);
    assertNotNull(((LazyTslCertificateSource) tsl).getLastCacheReloadingTime());
  }

  @Test
  public void getTslwithCacheExpirationTime() {
    configuration.setTslCacheExpirationTime(1337);
    LazyTslCertificateSource tsl = (LazyTslCertificateSource) tslManager.getTsl();
    assertNotNull(tsl.getCacheExpirationTime());
    assertEquals(1337, tsl.getCacheExpirationTime().longValue());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
    tslManager = new TslManager(configuration);
    evictTSLCache();
  }

}
