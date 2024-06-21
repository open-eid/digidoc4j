/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.ocsp;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataLoaderFactory;
import org.digidoc4j.OCSPSourceBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.asic.ocsp.BDocTMOcspSource;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class OCSPSourceBuilderTest extends AbstractTest {

  @Test
  public void buildTimestampOCSPSource_whenProfileIsNotSet() throws Exception {
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withConfiguration(
            this.configuration).build();
    Assert.assertEquals(CommonOCSPSource.class, source.getClass());
    TestAssert.assertOCSPSource(this.configuration, source, Constant.USER_AGENT_STRING);
  }

  @Test
  public void buildTimestampOCSPSource() throws Exception {
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withSignatureProfile(
            SignatureProfile.LT).withConfiguration(this.configuration).build();
    Assert.assertEquals(CommonOCSPSource.class, source.getClass());
    TestAssert.assertOCSPSource(this.configuration, source, Constant.USER_AGENT_STRING);
  }

  @Test
  public void buildTimemarkOCSPSource() throws Exception {
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withSignatureProfile(
            SignatureProfile.LT_TM).withSignatureValue(new byte[]{1, 2, 3}).withConfiguration(this.configuration).build();
    Assert.assertEquals(BDocTMOcspSource.class, source.getClass());
    TestAssert.assertOCSPSource(this.configuration, source, Constant.USER_AGENT_STRING);
  }

  @Test
  public void buildDefaultOCSPSource_customDataLoader() {
    DataLoader mockDataLoader = createMockDataLoader();
    configuration.setOcspDataLoaderFactory(createMockOcspDataLoaderFactory(mockDataLoader));
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.defaultOCSPSource().withConfiguration(configuration).build();
    Assert.assertSame(mockDataLoader, source.getDataLoader());
  }

  @Test
  public void buildTimemarkOCSPSource_customDataLoader() {
    DataLoader mockDataLoader = createMockDataLoader();
    configuration.setOcspDataLoaderFactory(createMockOcspDataLoaderFactory(mockDataLoader));
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withConfiguration(configuration)
            .withSignatureProfile(SignatureProfile.LT_TM).withSignatureValue(new byte[]{1, 2, 3}).build();
    Assert.assertSame(mockDataLoader, source.getDataLoader());
  }

  @Test
  public void buildTimestampOCSPSource_customDataLoader() {
    DataLoader mockDataLoader = createMockDataLoader();
    configuration.setOcspDataLoaderFactory(createMockOcspDataLoaderFactory(mockDataLoader));
    SKOnlineOCSPSource source = (SKOnlineOCSPSource) OCSPSourceBuilder.anOcspSource().withConfiguration(configuration)
            .withSignatureProfile(SignatureProfile.LT).build();
    Assert.assertSame(mockDataLoader, source.getDataLoader());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

  private DataLoaderFactory createMockOcspDataLoaderFactory(DataLoader dataLoader) {
    DataLoaderFactory dataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(dataLoader).when(dataLoaderFactory).create();
    return dataLoaderFactory;
  }

  private DataLoader createMockDataLoader() {
    return Mockito.mock(DataLoader.class);
  }

}
