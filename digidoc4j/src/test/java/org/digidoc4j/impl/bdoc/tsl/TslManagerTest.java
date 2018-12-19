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
import org.junit.Assert;
import org.junit.Test;

public class TslManagerTest extends AbstractTest {

  private TslManager tslManager;

  @Test
  public void getNewTsl() throws Exception {
    TSLCertificateSource tsl = this.tslManager.getTsl();
    Assert.assertNotNull(tsl);
  }

  @Test
  public void getCachedTsl() throws Exception {
    TSLCertificateSource tsl = this.tslManager.getTsl();
    TSLCertificateSource newTsl = this.tslManager.getTsl();
    Assert.assertSame(tsl, newTsl);
  }

  @Test
  public void getLazilyInitializedTsl() throws Exception {
    TSLCertificateSource tsl = this.tslManager.getTsl();
    Assert.assertTrue(tsl instanceof LazyTslCertificateSource);
    Assert.assertFalse(((LazyTslCertificateSource) tsl).getLastCacheReloadingTime() != null);
    Assert.assertTrue(tsl.getCertificatePool().getNumberOfCertificates() > 0);
    Assert.assertTrue(((LazyTslCertificateSource) tsl).getLastCacheReloadingTime() != null);
  }

  @Test
  public void getTslwithCacheExpirationTime() throws Exception {
    this.configuration.setTslCacheExpirationTime(1337);
    LazyTslCertificateSource tsl = (LazyTslCertificateSource) this.tslManager.getTsl();
    Assert.assertNotNull(tsl.getCacheExpirationTime());
    Assert.assertEquals(1337, tsl.getCacheExpirationTime().longValue());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.tslManager = new TslManager(this.configuration);
    this.evictTSLCache();
  }

}
