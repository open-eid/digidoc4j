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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.tsl.TslLoader;
import org.digidoc4j.test.MockSkDataLoader;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SkDataLoaderTest extends AbstractTest {

  @Test
  public void ocspDataLoader_withoutProxyConfiguration() {
    SkDataLoader dataLoader = new SkOCSPDataLoader(configuration);
    assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void ocspDataLoader_withProxyConfiguration() {
    configuration.setHttpProxyHost("proxyHost");
    configuration.setHttpProxyPort(1345);
    SkDataLoader dataLoader = new SkOCSPDataLoader(configuration);
    ProxyConfig config = dataLoader.getProxyConfig();
    assertNotNull(config);
    ProxyProperties httpProperties = config.getHttpProperties();
    assertNotNull(httpProperties);
    ProxyProperties httpsProperties = config.getHttpsProperties();
    assertNull(httpsProperties);
    assertEquals("proxyHost", httpProperties.getHost());
    assertEquals(1345, httpProperties.getPort());
    assertNull(httpProperties.getUser());
    assertNull(httpProperties.getPassword());
  }

  @Test
  public void dataLoader_withPasswordProxyConfiguration() {
    configuration.setHttpProxyHost("proxyHost");
    configuration.setHttpProxyPort(1345);
    configuration.setHttpProxyUser("proxyUser");
    configuration.setHttpProxyPassword("proxyPassword");
    SkDataLoader loader = new SkOCSPDataLoader(configuration);
    ProxyConfig config = loader.getProxyConfig();
    assertNotNull(config);
    ProxyProperties httpProperties = config.getHttpProperties();
    assertNotNull(httpProperties);
    ProxyProperties httpsProperties = config.getHttpsProperties();
    assertNull(httpsProperties);
    assertEquals("proxyHost", httpProperties.getHost());
    assertEquals(1345, httpProperties.getPort());
    assertEquals("proxyUser", httpProperties.getUser());
    assertArrayEquals("proxyPassword".toCharArray(), httpProperties.getPassword());
  }

  @Test
  @Disabled("Requires access to the proxy server")
  public void createSignAsicOverProxy() {
    TslLoader.invalidateCache();
    configuration.setHttpProxyHost("cache.elion.ee");
    configuration.setHttpProxyPort(8080);
    Container container = ContainerBuilder.aContainer().withConfiguration(configuration).
            withDataFile("src/test/resources/testFiles/helper-files/test.txt", MimeTypeEnum.TEXT.getMimeTypeString()).
            build();
    Signature signature = createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void dataLoader_withoutSslConfiguration_shouldNotSetSslValues() {
    MockSkDataLoader dataLoader = new MockSkDataLoader(configuration);
    assertNull(dataLoader.getSslKeystore());
    assertNull(dataLoader.getSslKeystoreType());
    assertNull(dataLoader.getSslKeystorePassword());
    assertNull(dataLoader.getSslTruststore());
    assertNull(dataLoader.getSslTruststoreType());
    assertNull(dataLoader.getSslTruststorePassword());
    assertFalse(dataLoader.isSslKeystoreTypeSet());
    assertFalse(dataLoader.isSslKeystorePasswordSet());
    assertFalse(dataLoader.isSslTruststoreTypeSet());
    assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withSslConfiguration_shouldSetSslValues() {
    configuration.setSslKeystorePath("classpath:testFiles/keystores/keystore.p12");
    configuration.setSslKeystoreType("PKCS12");
    configuration.setSslKeystorePassword("keystore-password");
    configuration.setSslTruststorePath("classpath:testFiles/keystores/truststore.jks");
    configuration.setSslTruststoreType("JKS");
    configuration.setSslTruststorePassword("digidoc4j-password");
    MockSkDataLoader dataLoader = new MockSkDataLoader(configuration);
    assertNotNull(dataLoader.getSslKeystore());
    assertEquals("PKCS12", dataLoader.getSslKeystoreType());
    assertArrayEquals("keystore-password".toCharArray(), dataLoader.getSslKeystorePassword());
    assertNotNull(dataLoader.getSslTruststore());
    assertEquals("JKS", dataLoader.getSslTruststoreType());
    assertArrayEquals("digidoc4j-password".toCharArray(), dataLoader.getSslTruststorePassword());
    assertTrue(dataLoader.isSslKeystoreTypeSet());
    assertTrue(dataLoader.isSslKeystorePasswordSet());
    assertTrue(dataLoader.isSslTruststoreTypeSet());
    assertTrue(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withMinimalSslConfiguration_shouldNotSetNullValues() {
    configuration.setSslKeystorePath("classpath:testFiles/keystores/keystore.jks");
    configuration.setSslTruststorePath("classpath:testFiles/keystores/truststore.jks");
    MockSkDataLoader dataLoader = new MockSkDataLoader(configuration);
    assertNotNull(dataLoader.getSslKeystore());
    assertNull(dataLoader.getSslKeystoreType());
    assertNull(dataLoader.getSslKeystorePassword());
    assertNotNull(dataLoader.getSslTruststore());
    assertNull(dataLoader.getSslTruststoreType());
    assertNull(dataLoader.getSslTruststorePassword());
    assertFalse(dataLoader.isSslKeystoreTypeSet());
    assertFalse(dataLoader.isSslKeystorePasswordSet());
    assertFalse(dataLoader.isSslTruststoreTypeSet());
    assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}
