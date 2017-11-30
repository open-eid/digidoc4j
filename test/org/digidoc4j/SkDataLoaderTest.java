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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.digidoc4j.impl.bdoc.CachingDataLoader;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.digidoc4j.impl.bdoc.tsl.TslLoader;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;

import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.http.proxy.ProxyProperties;

public class SkDataLoaderTest {

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(12189);

  static Configuration configuration = new Configuration(Configuration.Mode.TEST);
  static final String MOCK_PROXY_URL = "http://localhost:12189/";

  @Test
  public void getTimestampViaSpy() throws Exception {
    stubFor(post(urlEqualTo("/"))
        .willReturn(aResponse()
            .proxiedFrom(configuration.getTspSource())));

    byte[] tsRequest = new byte[]{48, 57, 2, 1, 1, 48, 49, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32, 2, 91, 64, 111, 35, -23, -19, -46, 57, -80, -63, -80, -74, 100, 72, 97, -47, -17, -35, -62, 102, 52, 116, 73, -10, -120, 115, 62, 2, 87, -29, -21, 1, 1, -1};
    SkDataLoader dataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(SignatureProfile.LT);
    byte[] response = dataLoader.post(MOCK_PROXY_URL, tsRequest);
    assertNotNull(response);
    TimeStampResponse timeStampResponse = new TimeStampResponse(response);
    assertEquals(0, timeStampResponse.getStatus());
    timeStampResponse.validate(new TimeStampRequest(tsRequest));

    verify(postRequestedFor(urlMatching("/")).
        withHeader("Content-Type", containing("application/timestamp-query")).
        withHeader("User-Agent", containing("LIB DigiDoc4j")));
  }

  @Test
  public void getOcspViaSpy() throws Exception {
    stubFor(post(urlEqualTo("/"))
        .willReturn(aResponse()
            .proxiedFrom(configuration.getOcspSource())));

    byte[] ocspRequest = new byte[] {48, 120, 48, 118, 48, 77, 48, 75, 48, 73, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, -20, -37, 96, 16, 51, -48, 76, 118, -7, -123, -78, 28, -40, 58, -45, -98, 2, -101, -109, 49, 4, 20, 73, -64, -14, 68, 57, 101, -43, -101, 70, 59, 13, 56, 96, -125, -79, -42, 45, 40, -122, -90, 2, 16, 83, 11, -28, 27, -68, 89, 124, 68, 87, 14, 43, 124, 19, -68, -6, 12, -94, 37, 48, 35, 48, 33, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 20, -55, 25, 66, -2, -90, 61, 30, -49, 20, -82, 91, 49, -4, -52, -64, 23, 106, 12, -114, 67};
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(SignatureProfile.LT);
    byte[] response = dataLoader.post(MOCK_PROXY_URL, ocspRequest);
    OCSPResp ocspResp = new OCSPResp(response);
    assertNotNull(ocspResp.getResponseObject());

    verify(postRequestedFor(urlMatching("/")).
        withHeader("Content-Type", containing("application/ocsp-request")).
        withHeader("User-Agent", containing("LIB DigiDoc4j")));
  }

  @Test
  public void ocspDataLoader_withoutProxyConfiguration() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void cachingDataLoader_withoutProxyConfiguration() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CachingDataLoader(configuration);
    assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void ocspDataLoader_withProxyConfiguration() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setHttpProxyHost("proxyHost");
    configuration.setHttpProxyPort(1345);
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    assertHTTPProxyConfigured(dataLoader, "proxyHost", 1345);
    assertProxyUsernamePasswordNotSet(dataLoader);
  }

  @Test
  public void cachingDataLoader_withProxyConfiguration() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setHttpProxyHost("proxyHost");
    configuration.setHttpProxyPort(1345);
    CommonsDataLoader dataLoader = new CachingDataLoader(configuration);
    assertHTTPProxyConfigured(dataLoader, "proxyHost", 1345);
    assertProxyUsernamePasswordNotSet(dataLoader);
  }

  @Test
  public void dataLoader_withPasswordProxyConfiguration() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setHttpProxyHost("proxyHost");
    configuration.setHttpProxyPort(1345);
    configuration.setHttpProxyUser("proxyUser");
    configuration.setHttpProxyPassword("proxyPassword");
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    assertHTTPProxyConfigured(dataLoader, "proxyHost", 1345);
    assertProxyUsernamePassword(dataLoader, "proxyPassword", "proxyUser");
  }

  @Test
  @Ignore("Requires access to the proxy server")
  public void createSignAsicOverProxy() throws Exception {
    TslLoader.invalidateCache();
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setHttpProxyHost("cache.elion.ee");
    configuration.setHttpProxyPort(8080);
    Container container = ContainerBuilder
        .aContainer(Constant.BDOC_CONTAINER_TYPE).
        withConfiguration(configuration).
        withDataFile("testFiles/helper-files/test.txt", MimeType.TEXT.getMimeTypeString()).
        build();
    Signature signature = TestDataBuilder.signContainer(container, SignatureProfile.LT);
    assertTrue(signature.validateSignature().isValid());

  }

  @Test
  public void dataLoader_withoutSslConfiguration_shouldNotSetSslValues() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    SkDataLoaderSpy dataLoader = new SkDataLoaderSpy(configuration);
    assertNull(dataLoader.getSslKeystorePath());
    assertNull(dataLoader.getSslKeystoreType());
    assertNull(dataLoader.getSslKeystorePassword());
    assertNull(dataLoader.getSslTruststorePath());
    assertNull(dataLoader.getSslTruststoreType());
    assertNull(dataLoader.getSslTruststorePassword());
    assertFalse(dataLoader.isSslKeystoreTypeSet());
    assertFalse(dataLoader.isSslKeystorePasswordSet());
    assertFalse(dataLoader.isSslTruststoreTypeSet());
    assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withSslConfiguration_shouldSetSslValues() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setSslKeystorePath("keystore.path");
    configuration.setSslKeystoreType("keystore.type");
    configuration.setSslKeystorePassword("keystore.password");
    configuration.setSslTruststorePath("truststore.path");
    configuration.setSslTruststoreType("truststore.type");
    configuration.setSslTruststorePassword("truststore.password");
    SkDataLoaderSpy dataLoader = new SkDataLoaderSpy(configuration);
    assertEquals("keystore.path", dataLoader.getSslKeystorePath());
    assertEquals("keystore.type", dataLoader.getSslKeystoreType());
    assertEquals("keystore.password", dataLoader.getSslKeystorePassword());
    assertEquals("truststore.path", dataLoader.getSslTruststorePath());
    assertEquals("truststore.type", dataLoader.getSslTruststoreType());
    assertEquals("truststore.password", dataLoader.getSslTruststorePassword());
    assertTrue(dataLoader.isSslKeystoreTypeSet());
    assertTrue(dataLoader.isSslKeystorePasswordSet());
    assertTrue(dataLoader.isSslTruststoreTypeSet());
    assertTrue(dataLoader.isSslTruststorePasswordSet());
  }

  @Test
  public void dataLoader_withMinimalSslConfiguration_shouldNotSetNullValues() throws Exception {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setSslKeystorePath("keystore.path");
    configuration.setSslTruststorePath("truststore.path");
    SkDataLoaderSpy dataLoader = new SkDataLoaderSpy(configuration);
    assertEquals("keystore.path", dataLoader.getSslKeystorePath());
    assertNull(dataLoader.getSslKeystoreType());
    assertNull(dataLoader.getSslKeystorePassword());
    assertEquals("truststore.path", dataLoader.getSslTruststorePath());
    assertNull(dataLoader.getSslTruststoreType());
    assertNull(dataLoader.getSslTruststorePassword());
    assertFalse(dataLoader.isSslKeystoreTypeSet());
    assertFalse(dataLoader.isSslKeystorePasswordSet());
    assertFalse(dataLoader.isSslTruststoreTypeSet());
    assertFalse(dataLoader.isSslTruststorePasswordSet());
  }

  private void assertHTTPProxyConfigured(CommonsDataLoader dataLoader, String proxyHost, int proxyPort) {
    ProxyConfig proxyConfig = dataLoader.getProxyConfig();
    assertNotNull(proxyConfig);
    ProxyProperties httpProperties = proxyConfig.getHttpProperties();
    ProxyProperties httpsProperties = proxyConfig.getHttpsProperties();

    assertEquals(proxyHost, httpProperties.getHost());
    assertEquals(proxyPort, httpProperties.getPort());
    //From DSS 5.1 not in use
    //assertTrue(httpProperties.isHttpEnabled());
    assertEquals(null, httpsProperties.getHost());
    assertEquals(0, httpsProperties.getPort());
    //assertTrue(httpsProperties.isHttpsEnabled());
  }

  private void assertHTTPSProxyConfigured(CommonsDataLoader dataLoader, String proxyHost, int proxyPort) {
    ProxyConfig proxyConfig = dataLoader.getProxyConfig();
    assertNotNull(proxyConfig);
    ProxyProperties httpProperties = proxyConfig.getHttpProperties();
    ProxyProperties httpsProperties = proxyConfig.getHttpProperties();

    assertEquals(null, httpProperties.getHost());
    assertEquals(0, httpProperties.getPort());

    assertEquals(proxyHost, httpsProperties.getHost());
    assertEquals(proxyPort, httpsProperties.getPort());
    //From DSS 5.1 not in use
    //assertTrue(httpsProperties.isHttpsEnabled());
  }

  private void assertProxyUsernamePasswordNotSet(CommonsDataLoader dataLoader) {
    ProxyConfig proxyConfig = dataLoader.getProxyConfig();
    ProxyProperties httpProperties = proxyConfig.getHttpProperties();
    ProxyProperties httpsProperties = proxyConfig.getHttpsProperties();

    assertTrue(isEmpty(httpProperties.getUser()));
    assertTrue(isEmpty(httpsProperties.getUser()));
    assertTrue(isEmpty(httpProperties.getPassword()));
    assertTrue(isEmpty(httpsProperties.getPassword()));
  }

  private void assertProxyUsernamePassword(SkDataLoader dataLoader, String proxyPassword, String proxyUser) {
    ProxyConfig proxyConfig = dataLoader.getProxyConfig();
    ProxyProperties httpProperties = proxyConfig.getHttpProperties();
    ProxyProperties httpsProperties = proxyConfig.getHttpsProperties();

    assertEquals(proxyUser, httpProperties.getUser());
    assertEquals(proxyUser, httpsProperties.getUser());
    assertEquals(proxyPassword, httpProperties.getPassword());
    assertEquals(proxyPassword, httpsProperties.getPassword());
  }

  public static class SkDataLoaderSpy extends SkDataLoader{

    private String sslKeystorePath;
    private String sslKeystoreType;
    private String sslKeystorePassword;
    private String sslTruststorePath;
    private String sslTruststoreType;
    private String sslTruststorePassword;

    private boolean isSslKeystoreTypeSet;
    private boolean sslKeystorePasswordSet;
    private boolean sslTruststoreTypeSet;
    private boolean sslTruststorePasswordSet;

    protected SkDataLoaderSpy(Configuration configuration) {
      super(configuration);
    }

    public String getSslKeystorePath() {
      return sslKeystorePath;
    }


    public void setSslKeystorePath(String sslKeystorePath) {
      this.sslKeystorePath = sslKeystorePath;
      super.setSslKeystorePath(sslKeystorePath);
    }

    public String getSslKeystoreType() {
      return sslKeystoreType;
    }


    public void setSslKeystoreType(String sslKeystoreType) {
      this.sslKeystoreType = sslKeystoreType;
      super.setSslKeystoreType(sslKeystoreType);
      isSslKeystoreTypeSet = true;
    }

    public String getSslKeystorePassword() {
      return sslKeystorePassword;
    }

    public void setSslKeystorePassword(String sslKeystorePassword) {
      this.sslKeystorePassword = sslKeystorePassword;
      super.setSslKeystorePassword(sslKeystorePassword);
      sslKeystorePasswordSet = true;
    }

    public String getSslTruststorePath() {
      return sslTruststorePath;
    }

    public void setSslTruststorePath(String sslTruststorePath) {
      this.sslTruststorePath = sslTruststorePath;
      super.setSslTruststorePath(sslTruststorePath);
    }

    public String getSslTruststoreType() {
      return sslTruststoreType;
    }

    public void setSslTruststoreType(String sslTruststoreType) {
      this.sslTruststoreType = sslTruststoreType;
      super.setSslTruststoreType(sslTruststoreType);
      sslTruststoreTypeSet = true;
    }

    public String getSslTruststorePassword() {
      return sslTruststorePassword;
    }

    public void setSslTruststorePassword(String sslTruststorePassword) {
      this.sslTruststorePassword = sslTruststorePassword;
      super.setSslTruststorePassword(sslTruststorePassword);
      sslTruststorePasswordSet = true;
    }

    public boolean isSslKeystoreTypeSet() {
      return isSslKeystoreTypeSet;
    }

    public boolean isSslKeystorePasswordSet() {
      return sslKeystorePasswordSet;
    }

    public boolean isSslTruststoreTypeSet() {
      return sslTruststoreTypeSet;
    }

    public boolean isSslTruststorePasswordSet() {
      return sslTruststorePasswordSet;
    }
  }
}
