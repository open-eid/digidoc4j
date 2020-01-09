package org.digidoc4j.impl;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Arrays;

public class AiaDataLoaderFactoryTest extends AbstractTest {

    @Test
    public void testDefaultAiaDataLoaderCreatedWhenNoCustomDataLoaderFactoryConfigured() {
        DataLoader dataLoader = new AiaDataLoaderFactory(configuration).create();
        Assert.assertTrue("Data loader should be of type " + CommonsDataLoader.class.getSimpleName(), dataLoader instanceof CommonsDataLoader);

        Assert.assertNull(((CommonsDataLoader) dataLoader).getProxyConfig());
        Assert.assertNull(((CommonsDataLoader) dataLoader).getSupportedSSLCipherSuites());
        Assert.assertNull(((CommonsDataLoader) dataLoader).getSupportedSSLProtocols());
    }

    @Test
    public void testDefaultAiaDataLoaderWithProxyConfigCreatedWhenNoCustomDataLoaderFactoryConfigured() {
        configuration.setHttpProxyHost("http://proxy.host");
        configuration.setHttpProxyPort(8080);
        configuration.setHttpsProxyHost("https://proxy.host");
        configuration.setHttpsProxyPort(8443);
        configuration.setHttpProxyUser("proxy-user");
        configuration.setHttpProxyPassword("proxy-password");

        DataLoader dataLoader = new AiaDataLoaderFactory(configuration).create();
        Assert.assertTrue("Data loader should be of type " + CommonsDataLoader.class.getSimpleName(), dataLoader instanceof CommonsDataLoader);

        Assert.assertNotNull(((CommonsDataLoader) dataLoader).getProxyConfig());
        Assert.assertNull(((CommonsDataLoader) dataLoader).getSupportedSSLCipherSuites());
        Assert.assertNull(((CommonsDataLoader) dataLoader).getSupportedSSLProtocols());
    }

    @Test
    public void testDefaultAiaDataLoaderWithSslConfigCreatedWhenNoCustomDataLoaderFactoryConfigured() {
        configuration.setSslTruststorePath("/ssl/truststore/path");
        configuration.setSslTruststorePassword("ssl-truststore-password");
        configuration.setSslTruststoreType("SSL_TRUSTSTORE_TYPE");
        configuration.setSupportedSslCipherSuites(Arrays.asList("supported_cipher_suite"));
        configuration.setSupportedSslProtocols(Arrays.asList("supported_ssl_protocol"));

        DataLoader dataLoader = new AiaDataLoaderFactory(configuration).create();
        Assert.assertTrue("Data loader should be of type " + CommonsDataLoader.class.getSimpleName(), dataLoader instanceof CommonsDataLoader);

        Assert.assertNull(((CommonsDataLoader) dataLoader).getProxyConfig());
        Assert.assertNotNull(((CommonsDataLoader) dataLoader).getSupportedSSLCipherSuites());
        Assert.assertNotNull(((CommonsDataLoader) dataLoader).getSupportedSSLProtocols());
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