package org.digidoc4j.impl;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class TspDataLoaderFactoryTest extends AbstractTest {

  private static final String MOCK_USER_AGENT_VALUE = "mock-user-agent-value";

  @Test
  public void testDefaultTspDataLoaderCreatedWhenCustomDataLoaderNotConfigured() {
    DataLoader dataLoader = new TspDataLoaderFactory(configuration, MOCK_USER_AGENT_VALUE).create();
    Assert.assertTrue("Data loader should be of type " + SkTimestampDataLoader.class.getSimpleName(), dataLoader instanceof SkTimestampDataLoader);
    Assert.assertEquals(MOCK_USER_AGENT_VALUE, ((SkTimestampDataLoader) dataLoader).getUserAgent());
  }

  @Test
  public void testCustomDataLoaderCreatedWhenCustomDataLoaderConfigured() {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();

    configuration.setTspDataLoaderFactory(mockDataLoaderFactory);
    DataLoader dataLoader = new TspDataLoaderFactory(configuration, MOCK_USER_AGENT_VALUE).create();
    Assert.assertSame(mockDataLoader, dataLoader);

    Mockito.verify(mockDataLoaderFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}