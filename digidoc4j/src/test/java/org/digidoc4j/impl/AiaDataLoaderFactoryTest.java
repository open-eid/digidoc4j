package org.digidoc4j.impl;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class AiaDataLoaderFactoryTest extends AbstractTest {

    @Test
    public void testDefaultAiaDataLoaderCreatedWhenNoCustomDataLoaderFactoryConfigured() {
        configuration.setConnectionTimeout(2345);
        configuration.setSocketTimeout(1234);

        DataLoader dataLoader = new AiaDataLoaderFactory(configuration, USER_AGENT_STRING).create();
        Assert.assertTrue("Data loader should be of type " + SimpleHttpGetDataLoader.class.getSimpleName(), dataLoader instanceof SimpleHttpGetDataLoader);

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
        DataLoader dataLoader = new AiaDataLoaderFactory(configuration, USER_AGENT_STRING).create();
        Assert.assertSame(mockDataLoader, dataLoader);

        Mockito.verify(mockDataLoaderFactory, Mockito.times(1)).create();
        Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
    }

    @Override
    protected void before() {
        configuration = Configuration.of(Configuration.Mode.TEST);
    }

}