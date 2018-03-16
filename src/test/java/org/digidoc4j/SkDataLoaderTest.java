/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.digidoc4j.impl.asic.CachingDataLoader;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.impl.asic.tsl.TslLoader;
import org.digidoc4j.test.MockSkDataLoader;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.http.proxy.ProxyProperties;

public class SkDataLoaderTest extends AbstractTest {

  private static final String MOCK_PROXY_URL = "http://localhost:12189/";

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(12189);

  @Test
  public void getTimestampViaSpy() throws Exception {
    WireMock.stubFor(WireMock.post(WireMock.urlEqualTo("/")).willReturn(WireMock.aResponse().proxiedFrom(this.configuration.getTspSource())));
    byte[] tsRequest = new byte[]{48, 57, 2, 1, 1, 48, 49, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32, 2, 91, 64, 111, 35, -23, -19, -46, 57, -80, -63, -80, -74, 100, 72, 97, -47, -17, -35, -62, 102, 52, 116, 73, -10, -120, 115, 62, 2, 87, -29, -21, 1, 1, -1};
    SkDataLoader dataLoader = SkDataLoader.timestamp(this.configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
    byte[] response = dataLoader.post(MOCK_PROXY_URL, tsRequest);
    Assert.assertNotNull(response);
    TimeStampResponse timeStampResponse = new TimeStampResponse(response);
    Assert.assertEquals(0, timeStampResponse.getStatus());
    timeStampResponse.validate(new TimeStampRequest(tsRequest));
    WireMock.verify(WireMock.postRequestedFor(WireMock.urlMatching("/")).
        withHeader("Content-Type", WireMock.containing("application/timestamp-query")).
        withHeader("User-Agent", WireMock.containing("LIB DigiDoc4j")));
  }

  @Test
  public void getOcspViaSpy() throws Exception {
    WireMock.stubFor(WireMock.post(WireMock.urlEqualTo("/")).willReturn(WireMock.aResponse()
        .proxiedFrom(configuration.getOcspSource())));
    byte[] ocspRequest = new byte[]{48, 120, 48, 118, 48, 77, 48, 75, 48, 73, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, -20, -37, 96, 16, 51, -48, 76, 118, -7, -123, -78, 28, -40, 58, -45, -98, 2, -101, -109, 49, 4, 20, 73, -64, -14, 68, 57, 101, -43, -101, 70, 59, 13, 56, 96, -125, -79, -42, 45, 40, -122, -90, 2, 16, 83, 11, -28, 27, -68, 89, 124, 68, 87, 14, 43, 124, 19, -68, -6, 12, -94, 37, 48, 35, 48, 33, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 20, -55, 25, 66, -2, -90, 61, 30, -49, 20, -82, 91, 49, -4, -52, -64, 23, 106, 12, -114, 67};
    SkDataLoader dataLoader = SkDataLoader.ocsp(this.configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
    byte[] response = dataLoader.post(MOCK_PROXY_URL, ocspRequest);
    OCSPResp ocspResp = new OCSPResp(response);
    Assert.assertNotNull(ocspResp.getResponseObject());
    WireMock.verify(WireMock.postRequestedFor(WireMock.urlMatching("/")).
        withHeader("Content-Type", WireMock.containing("application/ocsp-request")).
        withHeader("User-Agent", WireMock.containing("LIB DigiDoc4j")));
  }

  @Test
  public void ocspDataLoader_withoutProxyConfiguration() throws Exception {
    SkDataLoader dataLoader = SkDataLoader.ocsp(this.configuration);
    Assert.assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void cachingDataLoader_withoutProxyConfiguration() throws Exception {
    CommonsDataLoader dataLoader = new CachingDataLoader(this.configuration);
    Assert.assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void ocspDataLoader_withProxyConfiguration() throws Exception {
    this.configuration.setHttpProxyHost("proxyHost");
    this.configuration.setHttpProxyPort(1345);
    SkDataLoader dataLoader = SkDataLoader.ocsp(this.configuration);
    TestAssert.assertHTTPProxyIsConfigured(dataLoader, "proxyHost", 1345);
    TestAssert.assertProxyCredentialsAreUnset(dataLoader);
  }

  @Test
  public void cachingDataLoader_withProxyConfiguration() throws Exception {
    this.configuration.setHttpProxyHost("proxyHost");
    this.configuration.setHttpProxyPort(1345);
    CommonsDataLoader dataLoader = new CachingDataLoader(this.configuration);
    TestAssert.assertHTTPProxyIsConfigured(dataLoader, "proxyHost", 1345);
    TestAssert.assertProxyCredentialsAreUnset(dataLoader);
  }

  @Test
  public void dataLoader_withPasswordProxyConfiguration() throws Exception {
    this.configuration.setHttpProxyHost("proxyHost");
    this.configuration.setHttpProxyPort(1345);
    this.configuration.setHttpProxyUser("proxyUser");
    this.configuration.setHttpProxyPassword("proxyPassword");
    SkDataLoader loader = SkDataLoader.ocsp(this.configuration);
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
    Assert.assertNull(dataLoader.getSslKeystorePath());
    Assert.assertNull(dataLoader.getSslKeystoreType());
    Assert.assertNull(dataLoader.getSslKeystorePassword());
    Assert.assertNull(dataLoader.getSslTruststorePath());
    Assert.assertNull(dataLoader.getSslTruststoreType());
    Assert.assertNull(dataLoader.getSslTruststorePassword());
    Assert.assertFalse(dataLoader.isSslKeystoreTypeSet());
    Assert.assertFalse(dataLoader.isSslKeystorePasswordSet());
    Assert.assertFalse(dataLoader.isSslTruststoreTypeSet());
    Assert.assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withSslConfiguration_shouldSetSslValues() throws Exception {
    this.configuration.setSslKeystorePath("keystore.path");
    this.configuration.setSslKeystoreType("keystore.type");
    this.configuration.setSslKeystorePassword("keystore.password");
    this.configuration.setSslTruststorePath("truststore.path");
    this.configuration.setSslTruststoreType("truststore.type");
    this.configuration.setSslTruststorePassword("truststore.password");
    MockSkDataLoader dataLoader = new MockSkDataLoader(this.configuration);
    Assert.assertEquals("keystore.path", dataLoader.getSslKeystorePath());
    Assert.assertEquals("keystore.type", dataLoader.getSslKeystoreType());
    Assert.assertEquals("keystore.password", dataLoader.getSslKeystorePassword());
    Assert.assertEquals("truststore.path", dataLoader.getSslTruststorePath());
    Assert.assertEquals("truststore.type", dataLoader.getSslTruststoreType());
    Assert.assertEquals("truststore.password", dataLoader.getSslTruststorePassword());
    Assert.assertTrue(dataLoader.isSslKeystoreTypeSet());
    Assert.assertTrue(dataLoader.isSslKeystorePasswordSet());
    Assert.assertTrue(dataLoader.isSslTruststoreTypeSet());
    Assert.assertTrue(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withMinimalSslConfiguration_shouldNotSetNullValues() throws Exception {
    this.configuration.setSslKeystorePath("keystore.path");
    this.configuration.setSslTruststorePath("truststore.path");
    MockSkDataLoader dataLoader = new MockSkDataLoader(this.configuration);
    Assert.assertEquals("keystore.path", dataLoader.getSslKeystorePath());
    Assert.assertNull(dataLoader.getSslKeystoreType());
    Assert.assertNull(dataLoader.getSslKeystorePassword());
    Assert.assertEquals("truststore.path", dataLoader.getSslTruststorePath());
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
