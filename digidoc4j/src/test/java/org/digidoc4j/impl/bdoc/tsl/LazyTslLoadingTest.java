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

import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.digidoc4j.test.util.TestCommonUtil;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LazyTslLoadingTest extends AbstractTest {

  @Test
  public void createLazyCertificatePool() {
    TSLCertificateSource tsl = configuration.getTSL();
    SKCommonCertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setTrustedCertSources(tsl);
    ListCertificateSource listCertificateSource = certificateVerifier.getTrustedCertSources();
    assertEquals(tsl.getNumberOfCertificates(), listCertificateSource.getNumberOfCertificates());
  }

  @Test
  public void populateParameters_withoutDownloadingTsl() {
    evictTSLCache();
    assertTrue(isTSLCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    assertTrue(isTSLCacheEmpty());
    SKCommonCertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
    certificateVerifier.setTrustedCertSources(tsl);

    assertTrue(isTSLCacheEmpty());
    ListCertificateSource listCertificateSource = certificateVerifier.getTrustedCertSources();
    assertEquals(tsl.getNumberOfCertificates(), listCertificateSource.getNumberOfCertificates());
    assertFalse(isTSLCacheEmpty());
  }

  @Test
  public void tslCertSource_shouldNotRenewTslAutomatically_whenCacheIsNotExpired() {
    configuration.setTslCacheExpirationTime(10000);
    evictTSLCache();
    assertTrue(isTSLCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    assertThat(tsl.getCertificates(), not(empty()));
    assertFalse(isTSLCacheEmpty());
    long tslCacheModificationTime = getTSLCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    assertThat(tsl.getCertificates(), not(empty()));
    long newTslCacheModificationTime = getTSLCacheLastModificationTime();
    assertEquals(tslCacheModificationTime, newTslCacheModificationTime);
  }

  @Test
  public void tslCertCource_shouldRenewTslAutomatically_whenCacheIsExpired() {
    configuration.setTslCacheExpirationTime(100);
    evictTSLCache();
    assertTrue(isTSLCacheEmpty());
    TSLCertificateSource tsl = configuration.getTSL();
    assertThat(tsl.getCertificates(), not(empty()));
    assertFalse(isTSLCacheEmpty());
    long tslCacheModificationTime = getTSLCacheLastModificationTime();
    TestCommonUtil.sleepInSeconds(1);
    assertThat(tsl.getCertificates(), not(empty()));
    long newTslCacheModificationTime = getTSLCacheLastModificationTime();
    assertTrue(tslCacheModificationTime < newTslCacheModificationTime);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  public void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}
