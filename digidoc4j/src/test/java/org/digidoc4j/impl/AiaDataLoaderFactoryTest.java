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

public class AiaDataLoaderFactoryTest extends AbstractTest {

  @Test
  public void testDefaultAiaDataLoaderCreatedWhenNoCustomDataLoaderFactoryConfigured() {
    configuration.setConnectionTimeout(2345);
    configuration.setSocketTimeout(1234);

    DataLoader dataLoader = new AiaDataLoaderFactory(configuration).create();
    MatcherAssert.assertThat(dataLoader, Matchers.instanceOf(SimpleHttpGetDataLoader.class));

    Assert.assertEquals(5, ((SimpleHttpGetDataLoader) dataLoader).getFollowRedirects());
    Assert.assertEquals(Constant.USER_AGENT_STRING, ((SimpleHttpGetDataLoader) dataLoader).getUserAgent());
    Assert.assertEquals(2345, ((SimpleHttpGetDataLoader) dataLoader).getConnectTimeout());
    Assert.assertEquals(1234, ((SimpleHttpGetDataLoader) dataLoader).getReadTimeout());
  }

  @Test
  public void testDefaultAiaDataLoaderCreatedWhenNoCustomDataLoaderFactoryConfiguredAndCustomUserAgentSpecified() {
    configuration.setConnectionTimeout(2345);
    configuration.setSocketTimeout(1234);

    DataLoader dataLoader = new AiaDataLoaderFactory(configuration, USER_AGENT_STRING).create();
    MatcherAssert.assertThat(dataLoader, Matchers.instanceOf(SimpleHttpGetDataLoader.class));

    Assert.assertEquals(5, ((SimpleHttpGetDataLoader) dataLoader).getFollowRedirects());
    Assert.assertEquals(USER_AGENT_STRING, ((SimpleHttpGetDataLoader) dataLoader).getUserAgent());
    Assert.assertEquals(2345, ((SimpleHttpGetDataLoader) dataLoader).getConnectTimeout());
    Assert.assertEquals(1234, ((SimpleHttpGetDataLoader) dataLoader).getReadTimeout());
  }

  @Test
  public void testCustomDataLoaderCreatedWhenCustomDataLoaderConfigured() {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();

    configuration.setAiaDataLoaderFactory(mockDataLoaderFactory);
    DataLoader dataLoader = new AiaDataLoaderFactory(configuration).create();
    Assert.assertSame(mockDataLoader, dataLoader);

    Mockito.verify(mockDataLoaderFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
