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
import org.digidoc4j.test.TestAssert;
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
    TestAssert.assertHTTPProxyIsConfigured(dataLoader, "proxyHost", 1345);
    TestAssert.assertProxyCredentialsAreUnset(dataLoader);
  }

  @Test
  public void dataLoader_withPasswordProxyConfiguration() throws Exception {
    this.configuration.setHttpProxyHost("proxyHost");
    this.configuration.setHttpProxyPort(1345);
    this.configuration.setHttpProxyUser("proxyUser");
    this.configuration.setHttpProxyPassword("proxyPassword");
    SkDataLoader loader = new SkOCSPDataLoader(this.configuration);
    TestAssert.assertHTTPProxyIsConfigured(loader, "proxyHost", 1345);
    ProxyConfig config = loader.getProxyConfig();
    ProxyProperties httpProperties = config.getHttpProperties();
    ProxyProperties httpsProperties = config.getHttpsProperties();
    Assert.assertEquals("proxyUser", httpProperties.getUser());
    Assert.assertEquals("proxyUser", httpsProperties.getUser());
    Assert.assertEquals("proxyPassword", httpProperties.getPassword());
    Assert.assertEquals("proxyPassword", httpsProperties.getPassword());
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
    this.configuration.setSslKeystorePath("classpath:testFiles/keystores/keystore.jks");
    this.configuration.setSslKeystoreType("keystore.type");
    this.configuration.setSslKeystorePassword("keystore.password");
    this.configuration.setSslTruststorePath("classpath:testFiles/keystores/truststore.jks");
    this.configuration.setSslTruststoreType("truststore.type");
    this.configuration.setSslTruststorePassword("truststore.password");
    MockSkDataLoader dataLoader = new MockSkDataLoader(this.configuration);
    Assert.assertEquals("keystore.jks", dataLoader.getSslKeystore().getName());
    Assert.assertEquals("keystore.type", dataLoader.getSslKeystoreType());
    Assert.assertEquals("keystore.password", dataLoader.getSslKeystorePassword());
    Assert.assertEquals("truststore.jks", dataLoader.getSslTruststore().getName());
    Assert.assertEquals("truststore.type", dataLoader.getSslTruststoreType());
    Assert.assertEquals("truststore.password", dataLoader.getSslTruststorePassword());
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
    Assert.assertEquals("keystore.jks", dataLoader.getSslKeystore().getName());
    Assert.assertNull(dataLoader.getSslKeystoreType());
    Assert.assertNull(dataLoader.getSslKeystorePassword());
    Assert.assertEquals("truststore.jks", dataLoader.getSslTruststore().getName());
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
