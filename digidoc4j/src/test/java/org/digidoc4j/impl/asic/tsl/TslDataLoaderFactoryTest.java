package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.File;
import java.util.Arrays;

public class TslDataLoaderFactoryTest extends AbstractTest {

  private static final File MOCK_FILE_CACHE_DIRECTORY = new File("/mock/file/cache/dir");

  private static final int MOCK_TIMEOUT_CONNECTION = 273;
  private static final int MOCK_TIMEOUT_SOCKET = 84;

  @Test
  public void testDefaultFileCacheDataLoaderCreatedWhenNoCustomDataLoaderFactoryConfiguredAndTslLocationIsHttpUrl() {
    configuration.setTslLocation("http://tsl.host:8080/path");
    configuration.setConnectionTimeout(MOCK_TIMEOUT_CONNECTION);
    configuration.setSocketTimeout(MOCK_TIMEOUT_SOCKET);

    DataLoader dataLoader = new TslDataLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("Data loader should be of type " + FileCacheDataLoader.class.getSimpleName(), dataLoader instanceof FileCacheDataLoader);

    DataLoader nestedDataLoader = ((FileCacheDataLoader) dataLoader).getDataLoader();
    Assert.assertTrue("Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName(), nestedDataLoader instanceof CommonsDataLoader);
    Assert.assertEquals(MOCK_TIMEOUT_CONNECTION, ((CommonsDataLoader) nestedDataLoader).getTimeoutConnection());
    Assert.assertEquals(MOCK_TIMEOUT_SOCKET, ((CommonsDataLoader) nestedDataLoader).getTimeoutSocket());

    Assert.assertNull(((CommonsDataLoader) nestedDataLoader).getProxyConfig());
    Assert.assertNull(((CommonsDataLoader) nestedDataLoader).getSupportedSSLCipherSuites());
    Assert.assertNull(((CommonsDataLoader) nestedDataLoader).getSupportedSSLProtocols());
  }

  @Test
  public void testDefaultFileCacheDataLoaderWithProxyConfigCreatedWhenNoCustomDataLoaderFactoryConfiguredAndTslLocationIsHttpUrl() {
    configuration.setTslLocation("http://tsl.host:8080/path");
    configuration.setHttpProxyHost("http://proxy.host");
    configuration.setHttpProxyPort(8080);
    configuration.setHttpsProxyHost("https://proxy.host");
    configuration.setHttpsProxyPort(8443);
    configuration.setHttpProxyUser("proxy-user");
    configuration.setHttpProxyPassword("proxy-password");

    DataLoader dataLoader = new TslDataLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("Data loader should be of type " + FileCacheDataLoader.class.getSimpleName(), dataLoader instanceof FileCacheDataLoader);

    DataLoader nestedDataLoader = ((FileCacheDataLoader) dataLoader).getDataLoader();
    Assert.assertTrue("Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName(), nestedDataLoader instanceof CommonsDataLoader);

    Assert.assertNotNull(((CommonsDataLoader) nestedDataLoader).getProxyConfig());
    Assert.assertNull(((CommonsDataLoader) nestedDataLoader).getSupportedSSLCipherSuites());
    Assert.assertNull(((CommonsDataLoader) nestedDataLoader).getSupportedSSLProtocols());
  }

  @Test
  public void testDefaultFileCacheDataLoaderWithSslConfigCreatedWhenNoCustomDataLoaderFactoryConfiguredAndTslLocationIsHttpUrl() {
    configuration.setTslLocation("http://tsl.host:8080/path");
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    configuration.setSupportedSslCipherSuites(Arrays.asList("supported_cipher_suite"));
    configuration.setSupportedSslProtocols(Arrays.asList("supported_ssl_protocol"));

    DataLoader dataLoader = new TslDataLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("Data loader should be of type " + FileCacheDataLoader.class.getSimpleName(), dataLoader instanceof FileCacheDataLoader);

    DataLoader nestedDataLoader = ((FileCacheDataLoader) dataLoader).getDataLoader();
    Assert.assertTrue("Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName(), nestedDataLoader instanceof CommonsDataLoader);

    Assert.assertNotNull(((CommonsDataLoader) nestedDataLoader).getSupportedSSLCipherSuites());
    Assert.assertNotNull(((CommonsDataLoader) nestedDataLoader).getSupportedSSLProtocols());
    Assert.assertNull(((CommonsDataLoader) nestedDataLoader).getProxyConfig());
  }

  @Test
  public void testDefaultCommonsDataLoaderCreatedWhenNoCustomDataLoaderFactoryConfiguredAndTslLocationNotHttpUrl() {
    configuration.setTslLocation("/not/http/url");

    DataLoader dataLoader = new TslDataLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("Data loader should be of type " + CommonsDataLoader.class.getSimpleName(), dataLoader instanceof CommonsDataLoader);
  }

  @Test
  public void testCustomDataLoaderCreatedWhenCustomDataLoaderFactoryConfigured() {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();

    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);
    DataLoader dataLoader = new TslDataLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertSame(mockDataLoader, dataLoader);

    Mockito.verify(mockDataLoaderFactory, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

}