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
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.impl.asic.tsl.LazyCertificatePool;
import org.digidoc4j.test.util.TestCommonUtil;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.x509.CertificatePool;

public class LazyTslLoadingTest extends AbstractTest {

  @Test
  public void createLazyCertificatePool() throws Exception {
    TSLCertificateSource tsl = this.configuration.getTSL();
    SKCommonCertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setTrustedCertSource(tsl);
    CertificatePool certificatePool = certificateVerifier.createValidationPool();
    Assert.assertTrue(certificatePool instanceof LazyCertificatePool);
    Assert.assertEquals(tsl.getCertificatePool().getNumberOfCertificates(), certificatePool.getNumberOfCertificates());
  }

  @Test
  public void populateParameters_withoutDownloadingTsl() throws Exception {
    this.evictTSLCache();
    Assert.assertTrue(this.isTSLCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    Assert.assertTrue(this.isTSLCacheEmpty());
    SKCommonCertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setTrustedCertSource(tsl);
    CertificatePool certificatePool = certificateVerifier.createValidationPool();
    Assert.assertTrue(this.isTSLCacheEmpty());
    Assert.assertEquals(tsl.getCertificatePool().getNumberOfCertificates(), certificatePool.getNumberOfCertificates());
    Assert.assertFalse(this.isTSLCacheEmpty());
  }

  @Test
  public void tslCertSource_shouldNotRenewTslAutomatically_whenCacheIsNotExpired() throws Exception {
    this.configuration.setTslCacheExpirationTime(10000);
    this.evictTSLCache();
    Assert.assertTrue(this.isTSLCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    Assert.assertTrue(tsl.getCertificates().size() > 0);
    Assert.assertFalse(this.isTSLCacheEmpty());
    long tslCacheModificationTime = this.getTSLCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    Assert.assertTrue(tsl.getCertificates().size() > 0);
    long newTslCacheModificationTime = this.getTSLCacheLastModificationTime();
    Assert.assertEquals(tslCacheModificationTime, newTslCacheModificationTime);
  }

  @Test
  public void tslCertCource_shouldRenewTslAutomatically_whenCacheIsExpired() throws Exception {
    this.configuration.setTslCacheExpirationTime(100);
    this.evictTSLCache();
    Assert.assertTrue(this.isTSLCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    Assert.assertTrue(tsl.getCertificates().size() > 0);
    Assert.assertFalse(this.isTSLCacheEmpty());
    long tslCacheModificationTime = this.getTSLCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    Assert.assertTrue(tsl.getCertificates().size() > 0);
    long newTslCacheModificationTime = this.getTSLCacheLastModificationTime();
    Assert.assertTrue(tslCacheModificationTime < newTslCacheModificationTime);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  public void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
