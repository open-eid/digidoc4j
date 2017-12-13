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
import static org.junit.Assert.assertTrue;

import org.digidoc4j.Configuration;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.impl.asic.tsl.LazyCertificatePool;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.testutils.TSLHelper;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.x509.CertificatePool;

public class LazyTslLoadingTest {

  private Configuration configuration;

  @Before
  public void setUp() throws Exception {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

  @Test
  public void createLazyCertificatePool() throws Exception {
    TSLCertificateSource tsl = configuration.getTSL();
    SKCommonCertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setTrustedCertSource(tsl);
    CertificatePool certificatePool = certificateVerifier.createValidationPool();
    assertTrue(certificatePool instanceof LazyCertificatePool);
    assertEquals(tsl.getCertificatePool().getNumberOfCertificates(), certificatePool.getNumberOfCertificates());
  }

  @Test
  public void populateParameters_withoutDownloadingTsl() throws Exception {
    deleteTSLCache();
    assertTrue(isTslCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    assertTrue(isTslCacheEmpty());
    SKCommonCertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setTrustedCertSource(tsl);
    CertificatePool certificatePool = certificateVerifier.createValidationPool();
    assertTrue(isTslCacheEmpty());
    assertEquals(tsl.getCertificatePool().getNumberOfCertificates(), certificatePool.getNumberOfCertificates());
    assertFalse(isTslCacheEmpty());
  }

  @Test
  public void tslCertSource_shouldNotRenewTslAutomatically_whenCacheIsNotExpired() throws Exception {
    configuration.setTslCacheExpirationTime(10000);
    deleteTSLCache();
    assertTrue(isTslCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    assertTrue(tsl.getCertificates().size() > 0);
    assertFalse(isTslCacheEmpty());
    long tslCacheModificationTime = getCacheLastModificationTime();
    waitOneSecond();
    assertTrue(tsl.getCertificates().size() > 0);
    long newTslCacheModificationTime = getCacheLastModificationTime();
    assertEquals(tslCacheModificationTime, newTslCacheModificationTime);
  }

  @Test
  public void tslCertCource_shouldRenewTslAutomatically_whenCacheIsExpired() throws Exception {
    configuration.setTslCacheExpirationTime(100);
    deleteTSLCache();
    assertTrue(isTslCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    assertTrue(tsl.getCertificates().size() > 0);
    assertFalse(isTslCacheEmpty());
    long tslCacheModificationTime = getCacheLastModificationTime();
    waitOneSecond();
    assertTrue(tsl.getCertificates().size() > 0);
    long newTslCacheModificationTime = getCacheLastModificationTime();
    assertTrue(tslCacheModificationTime < newTslCacheModificationTime);
  }

  private void deleteTSLCache() {
    TSLHelper.deleteTSLCache();
  }

  private long getCacheLastModificationTime() {
    return TSLHelper.getCacheLastModificationTime();
  }

  private boolean isTslCacheEmpty() {
    return TSLHelper.isTslCacheEmpty();
  }

  private void waitOneSecond() throws InterruptedException {
    Thread.sleep(1000L); //Waiting is necessary to check changes in the cached files modification time
  }
}
