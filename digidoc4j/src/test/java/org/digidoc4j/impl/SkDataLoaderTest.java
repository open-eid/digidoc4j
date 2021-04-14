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

import eu.europa.esig.dss.model.MimeType;
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
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class SkDataLoaderTest extends AbstractTest {

  @Test
  public void ocspDataLoader_withoutProxyConfiguration() throws Exception {
    SkDataLoader dataLoader = new SkOCSPDataLoader(this.configuration);
    Assert.assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void ocspDataLoader_withProxyConfiguration() throws Exception {
    this.configuration.setHttpProxyHost("proxyHost");
    this.configuration.setHttpProxyPort(1345);
    SkDataLoader dataLoader = new SkOCSPDataLoader(this.configuration);
    ProxyConfig config = dataLoader.getProxyConfig();
    Assert.assertNotNull(config);
    ProxyProperties httpProperties = config.getHttpProperties();
    Assert.assertNotNull(httpProperties);
    ProxyProperties httpsProperties = config.getHttpsProperties();
    Assert.assertNull(httpsProperties);
    Assert.assertEquals("proxyHost", httpProperties.getHost());
    Assert.assertEquals(1345, httpProperties.getPort());
    Assert.assertNull(httpProperties.getUser());
    Assert.assertNull(httpProperties.getPassword());
  }

  @Test
  public void dataLoader_withPasswordProxyConfiguration() throws Exception {
    this.configuration.setHttpProxyHost("proxyHost");
    this.configuration.setHttpProxyPort(1345);
    this.configuration.setHttpProxyUser("proxyUser");
    this.configuration.setHttpProxyPassword("proxyPassword");
    SkDataLoader loader = new SkOCSPDataLoader(this.configuration);
    ProxyConfig config = loader.getProxyConfig();
    Assert.assertNotNull(config);
    ProxyProperties httpProperties = config.getHttpProperties();
    Assert.assertNotNull(httpProperties);
    ProxyProperties httpsProperties = config.getHttpsProperties();
    Assert.assertNull(httpsProperties);
    Assert.assertEquals("proxyHost", httpProperties.getHost());
    Assert.assertEquals(1345, httpProperties.getPort());
    Assert.assertEquals("proxyUser", httpProperties.getUser());
    Assert.assertEquals("proxyPassword", httpProperties.getPassword());
  }

  @Test
  @Ignore("Requires access to the proxy server")
  public void createSignAsicOverProxy() throws Exception {
    TslLoader.invalidateCache();
    this.configuration.setHttpProxyHost("cache.elion.ee");
    this.configuration.setHttpProxyPort(8080);
    Container container = ContainerBuilder.aContainer().withConfiguration(this.configuration).
            withDataFile("src/test/resources/testFiles/helper-files/test.txt", MimeType.TEXT.getMimeTypeString()).
            build();
    Signature signature = this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    Assert.assertTrue(signature.validateSignature().isValid());
  }

  @Test
  public void dataLoader_withoutSslConfiguration_shouldNotSetSslValues() throws Exception {
    MockSkDataLoader dataLoader = new MockSkDataLoader(this.configuration);
    Assert.assertNull(dataLoader.getSslKeystore());
    Assert.assertNull(dataLoader.getSslKeystoreType());
    Assert.assertNull(dataLoader.getSslKeystorePassword());
    Assert.assertNull(dataLoader.getSslTruststore());
    Assert.assertNull(dataLoader.getSslTruststoreType());
    Assert.assertNull(dataLoader.getSslTruststorePassword());
    Assert.assertFalse(dataLoader.isSslKeystoreTypeSet());
    Assert.assertFalse(dataLoader.isSslKeystorePasswordSet());
    Assert.assertFalse(dataLoader.isSslTruststoreTypeSet());
    Assert.assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withSslConfiguration_shouldSetSslValues() throws Exception {
    this.configuration.setSslKeystorePath("classpath:testFiles/keystores/keystore.p12");
    this.configuration.setSslKeystoreType("PKCS12");
    this.configuration.setSslKeystorePassword("keystore-password");
    this.configuration.setSslTruststorePath("classpath:testFiles/keystores/truststore.jks");
    this.configuration.setSslTruststoreType("JKS");
    this.configuration.setSslTruststorePassword("digidoc4j-password");
    MockSkDataLoader dataLoader = new MockSkDataLoader(this.configuration);
    Assert.assertNotNull(dataLoader.getSslKeystore());
    Assert.assertEquals("PKCS12", dataLoader.getSslKeystoreType());
    Assert.assertEquals("keystore-password", dataLoader.getSslKeystorePassword());
    Assert.assertNotNull(dataLoader.getSslTruststore());
    Assert.assertEquals("JKS", dataLoader.getSslTruststoreType());
    Assert.assertEquals("digidoc4j-password", dataLoader.getSslTruststorePassword());
    Assert.assertTrue(dataLoader.isSslKeystoreTypeSet());
    Assert.assertTrue(dataLoader.isSslKeystorePasswordSet());
    Assert.assertTrue(dataLoader.isSslTruststoreTypeSet());
    Assert.assertTrue(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withMinimalSslConfiguration_shouldNotSetNullValues() throws Exception {
    this.configuration.setSslKeystorePath("classpath:testFiles/keystores/keystore.jks");
    this.configuration.setSslTruststorePath("classpath:testFiles/keystores/truststore.jks");
    MockSkDataLoader dataLoader = new MockSkDataLoader(this.configuration);
    Assert.assertNotNull(dataLoader.getSslKeystore());
    Assert.assertNull(dataLoader.getSslKeystoreType());
    Assert.assertNull(dataLoader.getSslKeystorePassword());
    Assert.assertNotNull(dataLoader.getSslTruststore());
    Assert.assertNull(dataLoader.getSslTruststoreType());
    Assert.assertNull(dataLoader.getSslTruststorePassword());
    Assert.assertFalse(dataLoader.isSslKeystoreTypeSet());
    Assert.assertFalse(dataLoader.isSslKeystorePasswordSet());
    Assert.assertFalse(dataLoader.isSslTruststoreTypeSet());
    Assert.assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}
