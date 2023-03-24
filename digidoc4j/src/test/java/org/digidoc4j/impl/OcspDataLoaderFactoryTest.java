/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataLoaderFactory;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class OcspDataLoaderFactoryTest extends AbstractTest {

  private static final String MOCK_USER_AGENT_VALUE = "mock-user-agent-value";

  @Test
  public void testDefaultOcspDataLoaderCreatedWhenCustomDataLoaderNotConfigured() {
    DataLoader dataLoader = new OcspDataLoaderFactory(configuration).create();
    MatcherAssert.assertThat(dataLoader, Matchers.instanceOf(SkOCSPDataLoader.class));
    Assert.assertEquals(Constant.USER_AGENT_STRING, ((SkOCSPDataLoader) dataLoader).getUserAgent());
  }

  @Test
  public void testDefaultOcspDataLoaderCreatedWhenCustomDataLoaderNotConfiguredAndCustomUserAgentSpecified() {
    DataLoader dataLoader = new OcspDataLoaderFactory(configuration, MOCK_USER_AGENT_VALUE).create();
    MatcherAssert.assertThat(dataLoader, Matchers.instanceOf(SkOCSPDataLoader.class));
    Assert.assertEquals(MOCK_USER_AGENT_VALUE, ((SkOCSPDataLoader) dataLoader).getUserAgent());
  }

  @Test
  public void testCustomDataLoaderCreatedWhenCustomDataLoaderConfigured() {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();

    configuration.setOcspDataLoaderFactory(mockDataLoaderFactory);
    DataLoader dataLoader = new OcspDataLoaderFactory(configuration, MOCK_USER_AGENT_VALUE).create();
    Assert.assertSame(mockDataLoader, dataLoader);

    Mockito.verify(mockDataLoaderFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}