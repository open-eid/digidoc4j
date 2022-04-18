/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DSSFileLoaderFactory;
import org.digidoc4j.DataLoaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.File;
import java.util.Collections;

public class TslFileLoaderFactoryTest extends AbstractTest {

  private static final File MOCK_FILE_CACHE_DIRECTORY = new File("/mock/file/cache/dir");

  private static final int MOCK_TIMEOUT_CONNECTION = 273;
  private static final int MOCK_TIMEOUT_SOCKET = 84;

  @Test
  public void testDefaultFileCacheDataLoaderCreatedWhenNoCustomLoaderFactoriesConfigured() {
    configuration.setConnectionTimeout(MOCK_TIMEOUT_CONNECTION);
    configuration.setSocketTimeout(MOCK_TIMEOUT_SOCKET);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("File loader should be of type " + FileCacheDataLoader.class.getSimpleName(), fileLoader instanceof FileCacheDataLoader);
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    Assert.assertTrue("Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName(), nestedDataLoader instanceof CommonsDataLoader);
    CommonsDataLoader nestedCommonsDataLoader = (CommonsDataLoader) nestedDataLoader;

    Assert.assertEquals(MOCK_TIMEOUT_CONNECTION, nestedCommonsDataLoader.getTimeoutConnection());
    Assert.assertEquals(MOCK_TIMEOUT_SOCKET, nestedCommonsDataLoader.getTimeoutSocket());

    Assert.assertNull(nestedCommonsDataLoader.getProxyConfig());
    Assert.assertNull(nestedCommonsDataLoader.getSupportedSSLCipherSuites());
    Assert.assertNull(nestedCommonsDataLoader.getSupportedSSLProtocols());
  }

  @Test
  public void testDefaultFileCacheDataLoaderWithProxyConfigCreatedWhenNoCustomLoaderFactoriesConfigured() {
    configuration.setHttpProxyHost("http://proxy.host");
    configuration.setHttpProxyPort(8080);
    configuration.setHttpsProxyHost("https://proxy.host");
    configuration.setHttpsProxyPort(8443);
    configuration.setHttpProxyUser("proxy-user");
    configuration.setHttpProxyPassword("proxy-password");

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("File loader should be of type " + FileCacheDataLoader.class.getSimpleName(), fileLoader instanceof FileCacheDataLoader);
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    Assert.assertTrue("Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName(), nestedDataLoader instanceof CommonsDataLoader);
    CommonsDataLoader nestedCommonsDataLoader = (CommonsDataLoader) nestedDataLoader;

    Assert.assertNotNull(nestedCommonsDataLoader.getProxyConfig());
    Assert.assertNull(nestedCommonsDataLoader.getSupportedSSLCipherSuites());
    Assert.assertNull(nestedCommonsDataLoader.getSupportedSSLProtocols());
  }

  @Test
  public void testDefaultFileCacheDataLoaderWithSslConfigCreatedWhenNoCustomLoaderFactoriesConfigured() {
    configuration.setTslLocation("http://tsl.host:8080/path");
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    configuration.setSupportedSslCipherSuites(Collections.singletonList("supported_cipher_suite"));
    configuration.setSupportedSslProtocols(Collections.singletonList("supported_ssl_protocol"));

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("File loader should be of type " + FileCacheDataLoader.class.getSimpleName(), fileLoader instanceof FileCacheDataLoader);
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    Assert.assertTrue("Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName(), nestedDataLoader instanceof CommonsDataLoader);
    CommonsDataLoader nestedCommonsDataLoader = (CommonsDataLoader) nestedDataLoader;

    Assert.assertNotNull(nestedCommonsDataLoader.getSupportedSSLCipherSuites());
    Assert.assertNotNull(nestedCommonsDataLoader.getSupportedSSLProtocols());
    Assert.assertNull(nestedCommonsDataLoader.getProxyConfig());
  }

  @Test
  public void testCustomFileLoaderCreatedWhenCustomFileLoaderFactoryConfigured() {
    DSSFileLoader mockFileLoader = Mockito.mock(DSSFileLoader.class);
    DSSFileLoaderFactory mockFileLoaderFactory = Mockito.mock(DSSFileLoaderFactory.class);
    Mockito.doReturn(mockFileLoader).when(mockFileLoaderFactory).create();
    configuration.setTslFileLoaderFactory(mockFileLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertSame(mockFileLoader, fileLoader);

    Mockito.verify(mockFileLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockFileLoaderFactory, mockFileLoader);
  }

  @Test
  public void testCustomFileLoaderCreatedWhenCustomFileLoaderFactoryAndCustomDataLoaderFactoryConfigured() {
    DSSFileLoader mockFileLoader = Mockito.mock(DSSFileLoader.class);
    DSSFileLoaderFactory mockFileLoaderFactory = Mockito.mock(DSSFileLoaderFactory.class);
    Mockito.doReturn(mockFileLoader).when(mockFileLoaderFactory).create();
    configuration.setTslFileLoaderFactory(mockFileLoaderFactory);

    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertSame(mockFileLoader, fileLoader);

    Mockito.verify(mockFileLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockFileLoaderFactory, mockFileLoader, mockDataLoaderFactory);
  }

  @Test
  public void testCustomFileLoaderCreatedWhenCustomDataLoaderFactoryConfiguredWhichCreatesDataLoadersImplementingFileLoaderInterface() {
    DataLoader mockDataAndFileLoader = Mockito.mock(DataLoaderWithFileLoaderInterface.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataAndFileLoader).when(mockDataLoaderFactory).create();
    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertSame(mockDataAndFileLoader, fileLoader);

    Mockito.verify(mockDataLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockDataAndFileLoader, mockDataAndFileLoader);
  }

  @Test
  public void testFileCacheDataLoaderWrappingCustomDataLoaderCreatedWhenCustomDataLoaderFactoryConfigured() {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();
    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, MOCK_FILE_CACHE_DIRECTORY).create();
    Assert.assertTrue("File loader should be of type " + FileCacheDataLoader.class.getSimpleName(), fileLoader instanceof FileCacheDataLoader);
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    Assert.assertSame(mockDataLoader, nestedDataLoader);

    Mockito.verify(mockDataLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  interface DataLoaderWithFileLoaderInterface extends DataLoader, DSSFileLoader {}

}