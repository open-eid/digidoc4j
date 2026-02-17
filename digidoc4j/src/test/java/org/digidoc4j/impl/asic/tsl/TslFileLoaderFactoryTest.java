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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.File;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class TslFileLoaderFactoryTest extends AbstractTest {

  private static final int MOCK_TIMEOUT_CONNECTION = 273;
  private static final int MOCK_TIMEOUT_SOCKET = 84;

  @TempDir
  File tslFileCacheDirectory;

  @Test
  void testDefaultFileCacheDataLoaderCreatedWhenNoCustomLoaderFactoriesConfigured() throws Exception {
    configuration.setConnectionTimeout(MOCK_TIMEOUT_CONNECTION);
    configuration.setSocketTimeout(MOCK_TIMEOUT_SOCKET);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertInstanceOf(FileCacheDataLoader.class, fileLoader, "File loader should be of type " + FileCacheDataLoader.class.getSimpleName());
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    assertInstanceOf(CommonsDataLoader.class, nestedDataLoader, "Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName());
    CommonsDataLoader nestedCommonsDataLoader = (CommonsDataLoader) nestedDataLoader;

    assertEquals(MOCK_TIMEOUT_CONNECTION, nestedCommonsDataLoader.getTimeoutConnection());
    assertEquals(MOCK_TIMEOUT_SOCKET, nestedCommonsDataLoader.getTimeoutSocket());

    assertNull(nestedCommonsDataLoader.getProxyConfig());
    assertArrayEquals(
            configuration.getSupportedSslCipherSuites().toArray(new String[0]),
            nestedCommonsDataLoader.getSupportedSSLCipherSuites()
    );
    assertArrayEquals(
            configuration.getSupportedSslProtocols().toArray(new String[0]),
            nestedCommonsDataLoader.getSupportedSSLProtocols()
    );
  }

  @Test
  void testDefaultFileCacheDataLoaderWithProxyConfigCreatedWhenNoCustomLoaderFactoriesConfigured() throws Exception {
    configuration.setHttpProxyHost("http://proxy.host");
    configuration.setHttpProxyPort(8080);
    configuration.setHttpsProxyHost("https://proxy.host");
    configuration.setHttpsProxyPort(8443);
    configuration.setHttpProxyUser("proxy-user");
    configuration.setHttpProxyPassword("proxy-password");

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertInstanceOf(FileCacheDataLoader.class, fileLoader, "File loader should be of type " + FileCacheDataLoader.class.getSimpleName());
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    assertInstanceOf(CommonsDataLoader.class, nestedDataLoader, "Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName());
    CommonsDataLoader nestedCommonsDataLoader = (CommonsDataLoader) nestedDataLoader;

    assertNotNull(nestedCommonsDataLoader.getProxyConfig());
    assertArrayEquals(
            configuration.getSupportedSslCipherSuites().toArray(new String[0]),
            nestedCommonsDataLoader.getSupportedSSLCipherSuites()
    );
    assertArrayEquals(
            configuration.getSupportedSslProtocols().toArray(new String[0]),
            nestedCommonsDataLoader.getSupportedSSLProtocols()
    );
  }

  @Test
  void testDefaultFileCacheDataLoaderWithSslConfigCreatedWhenNoCustomLoaderFactoriesConfigured() throws Exception {
    configuration.setLotlLocation("http://lotl.host:8080/path");
    configuration.setSslTruststorePath("classpath:testFiles/truststores/empty-truststore.p12");
    configuration.setSslTruststorePassword("digidoc4j-password");
    configuration.setSslTruststoreType("PKCS12");
    configuration.setSupportedSslCipherSuites(Collections.singletonList("supported_cipher_suite"));
    configuration.setSupportedSslProtocols(Collections.singletonList("supported_ssl_protocol"));

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertInstanceOf(FileCacheDataLoader.class, fileLoader, "File loader should be of type " + FileCacheDataLoader.class.getSimpleName());
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    assertInstanceOf(CommonsDataLoader.class, nestedDataLoader, "Nested data loader should be of type " + CommonsDataLoader.class.getSimpleName());
    CommonsDataLoader nestedCommonsDataLoader = (CommonsDataLoader) nestedDataLoader;

    assertArrayEquals(
            new String[] {"supported_cipher_suite"},
            nestedCommonsDataLoader.getSupportedSSLCipherSuites()
    );
    assertArrayEquals(
            new String[] {"supported_ssl_protocol"},
            nestedCommonsDataLoader.getSupportedSSLProtocols()
    );
    assertNull(nestedCommonsDataLoader.getProxyConfig());
  }

  @Test
  void testCustomFileLoaderCreatedWhenCustomFileLoaderFactoryConfigured() throws Exception {
    DSSFileLoader mockFileLoader = Mockito.mock(DSSFileLoader.class);
    DSSFileLoaderFactory mockFileLoaderFactory = Mockito.mock(DSSFileLoaderFactory.class);
    Mockito.doReturn(mockFileLoader).when(mockFileLoaderFactory).create();
    configuration.setTslFileLoaderFactory(mockFileLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertSame(mockFileLoader, fileLoader);

    Mockito.verify(mockFileLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockFileLoaderFactory, mockFileLoader);
  }

  @Test
  void testCustomFileLoaderCreatedWhenCustomFileLoaderFactoryAndCustomDataLoaderFactoryConfigured() throws Exception {
    DSSFileLoader mockFileLoader = Mockito.mock(DSSFileLoader.class);
    DSSFileLoaderFactory mockFileLoaderFactory = Mockito.mock(DSSFileLoaderFactory.class);
    Mockito.doReturn(mockFileLoader).when(mockFileLoaderFactory).create();
    configuration.setTslFileLoaderFactory(mockFileLoaderFactory);

    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertSame(mockFileLoader, fileLoader);

    Mockito.verify(mockFileLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockFileLoaderFactory, mockFileLoader, mockDataLoaderFactory);
  }

  @Test
  void testCustomFileLoaderCreatedWhenCustomDataLoaderFactoryConfiguredWhichCreatesDataLoadersImplementingFileLoaderInterface() throws Exception {
    DataLoader mockDataAndFileLoader = Mockito.mock(DataLoaderWithFileLoaderInterface.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataAndFileLoader).when(mockDataLoaderFactory).create();
    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertSame(mockDataAndFileLoader, fileLoader);

    Mockito.verify(mockDataLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockDataAndFileLoader, mockDataAndFileLoader);
  }

  @Test
  void testFileCacheDataLoaderWrappingCustomDataLoaderCreatedWhenCustomDataLoaderFactoryConfigured() throws Exception {
    DataLoader mockDataLoader = Mockito.mock(DataLoader.class);
    DataLoaderFactory mockDataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(mockDataLoader).when(mockDataLoaderFactory).create();
    configuration.setTslDataLoaderFactory(mockDataLoaderFactory);

    DSSFileLoader fileLoader = new TslFileLoaderFactory(configuration, tslFileCacheDirectory).create();
    assertInstanceOf(FileCacheDataLoader.class, fileLoader, "File loader should be of type " + FileCacheDataLoader.class.getSimpleName());
    FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) fileLoader;

    DataLoader nestedDataLoader = fileCacheDataLoader.getDataLoader();
    assertSame(mockDataLoader, nestedDataLoader);

    Mockito.verify(mockDataLoaderFactory).create();
    Mockito.verifyNoMoreInteractions(mockDataLoaderFactory, mockDataLoader);
  }

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  interface DataLoaderWithFileLoaderInterface extends DataLoader, DSSFileLoader {}

}
