package org.digidoc4j.impl;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class OcspDataLoaderFactoryTest extends AbstractTest {

  private static final String MOCK_USER_AGENT_VALUE = "mock-user-agent-value";

  @Test
  public void testDefaultOcspDataLoaderCreatedWhenCustomDataLoaderNotConfigured() {
    DataLoader dataLoader = new OcspDataLoaderFactory(configuration, MOCK_USER_AGENT_VALUE).create();
    Assert.assertTrue("Data loader should be of type " + SkOCSPDataLoader.class.getSimpleName(), dataLoader instanceof SkOCSPDataLoader);
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