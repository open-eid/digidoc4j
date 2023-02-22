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
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import org.digidoc4j.AIASourceFactory;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class AiaSourceFactoryTest extends AbstractTest {

  @Test
  public void testDefaultAiaSourceCreatedWhenNoCustomDataLoaderFactoryConfigured() {
    AIASource aiaSource = new AiaSourceFactory(configuration).create();
    MatcherAssert.assertThat(aiaSource, Matchers.instanceOf(DefaultAIASource.class));
    // It is currently not possible to access the data loader wrapped inside the DefaultAIASource
  }

  @Test
  public void testCustomAiaSourceCreatedWhenCustomAiaSourceFactoryConfigured() {
    AIASource mockAiaSource = Mockito.mock(AIASource.class);
    AIASourceFactory mockAiaSourceFactory = Mockito.mock(AIASourceFactory.class);
    Mockito.doReturn(mockAiaSource).when(mockAiaSourceFactory).create();
    configuration.setAiaSourceFactory(mockAiaSourceFactory);

    AIASource aiaSource = new AiaSourceFactory(configuration).create();
    Assert.assertSame(mockAiaSource, aiaSource);

    Mockito.verify(mockAiaSourceFactory).create();
    Mockito.verifyNoMoreInteractions(mockAiaSourceFactory, mockAiaSource);
  }

  @Test
  public void testCustomAiaSourceCreatedWhenCustomAiaSourceFactoryAndCustomAiaDataLoaderFactoryConfigured() {
    AIASource mockAiaSource = Mockito.mock(AIASource.class);
    AIASourceFactory mockAiaSourceFactory = Mockito.mock(AIASourceFactory.class);
    Mockito.doReturn(mockAiaSource).when(mockAiaSourceFactory).create();
    configuration.setAiaSourceFactory(mockAiaSourceFactory);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    configuration.setAiaDataLoaderFactory(mockDataLoaderFactory);

    AIASource aiaSource = new AiaSourceFactory(configuration).create();
    Assert.assertSame(mockAiaSource, aiaSource);

    Mockito.verify(mockAiaSourceFactory).create();
    Mockito.verifyNoMoreInteractions(mockAiaSourceFactory, mockAiaSource, mockDataLoaderFactory);
  }

  @Test
  public void testCustomAiaSourceCreatedWhenCustomAiaDataLoaderFactoryConfiguredAndNoCustomAiaSourceFactoryConfigured() {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();
    configuration.setAiaDataLoaderFactory(mockDataLoaderFactory);

    AIASource aiaSource = new AiaSourceFactory(configuration).create();
    MatcherAssert.assertThat(aiaSource, Matchers.instanceOf(DefaultAIASource.class));
    // It is currently not possible to access the data loader wrapped inside the DefaultAIASource
    Mockito.verify(mockDataLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
