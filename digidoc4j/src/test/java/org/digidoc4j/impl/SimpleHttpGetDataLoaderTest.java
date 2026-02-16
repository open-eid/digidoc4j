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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class SimpleHttpGetDataLoaderTest {

  private static final byte[] MOCK_RESPONSE = new byte[] {0, 1, 2, 3};
  private static final byte[] MOCK_REDIRECT_RESPONSE = "\tRedirect Page\n".getBytes(StandardCharsets.UTF_8);
  private static final byte[] MOCK_REDIRECT_RESPONSE_2 = "\tSome Other Page\n".getBytes(StandardCharsets.UTF_8);

  private static final List<Integer> ALLOWED_REDIRECT_STATUSES = Arrays.asList(
          HttpURLConnection.HTTP_MOVED_PERM, HttpURLConnection.HTTP_MOVED_TEMP, HttpURLConnection.HTTP_SEE_OTHER, 307, 308
  );

  private static final String REQUEST_PATH = "/path";
  private static final String REDIRECT_PATH = "/redirect/target";
  private static final String REDIRECT_PATH_2 = "/another/redirect/location";
  private static final String LOCATION_HEADER = "Location";

  @RegisterExtension
  static WireMockExtension wireMock = WireMockExtension.newInstance()
          .options(WireMockConfiguration.wireMockConfig().dynamicPort())
          .build();

  @RegisterExtension
  static WireMockExtension wireMockHttps = WireMockExtension.newInstance()
          .options(WireMockConfiguration.wireMockConfig().dynamicHttpsPort()
          .keystorePath("src/test/resources/testFiles/keystores/server-localhost.jks")
          .keystorePassword("digidoc4j-password")
          .keyManagerPassword("digidoc4j-password").keystoreType("JKS"))
          .build();

  private Appender<ILoggingEvent> mockedAppender;

  @BeforeEach
  public void setUpLoggingEnvironment() {
    Logger logger = (Logger) LoggerFactory.getLogger(SimpleHttpGetDataLoader.class.getName());
    mockedAppender = (Appender<ILoggingEvent>) Mockito.mock(Appender.class);
    logger.addAppender(mockedAppender);
    logger.setLevel(Level.DEBUG);
  }


  @Test
  public void requestShouldReturnResponseBytesOnHttp200_NoContentLengthHeader() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(200).withBody(MOCK_RESPONSE)));
    byte[] response = createDataLoader(0).request(wireMock.url(REQUEST_PATH), true);
    assertResponseForStatus(200, MOCK_RESPONSE, response);
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
    assertLogInOrder(
            Matchers.equalTo("Reading response of unspecified size")
    );
  }

  @Test
  public void requestShouldReturnResponseBytesOnHttp200_ValidContentLengthHeader() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(200)
            .withHeader("Content-Length", Integer.toString(MOCK_RESPONSE.length)).withBody(MOCK_RESPONSE)));
    byte[] response = createDataLoader(0).request(wireMock.url(REQUEST_PATH), true);
    assertResponseForStatus(200, MOCK_RESPONSE, response);
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
    assertLogInOrder(
            Matchers.equalTo("Reading response of specific size: " + MOCK_RESPONSE.length)
    );
  }

  @Test
  public void requestShouldFailToReturnResponseOnHttp200_ContentLengthHeaderTooLarge() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(200)
            .withHeader("Content-Length", Long.toString(Integer.MAX_VALUE + 1L)).withBody(new byte[1])));
    try {
      createDataLoader(0).request(wireMock.url(REQUEST_PATH), true);
      fail("Should have thrown an exception");
    } catch (Exception ex) {
      assertEquals("Unsupported Content-Length: " + (Integer.MAX_VALUE + 1L), ex.getMessage());
    }
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldNotRedirectOnHttp3xx_RedirectsNotEnabled() {
    for (int status = 300; status <= 399; ++status) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withBody(MOCK_REDIRECT_RESPONSE)));
      byte[] response = createDataLoader(0).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_REDIRECT_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldNotRedirectOnHttp3xx_NoLocationProvided_RedirectsEnabled() {
    for (int status = 300; status <= 399; ++status) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withBody(MOCK_REDIRECT_RESPONSE)));
      byte[] response = createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_REDIRECT_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldNotFollowRedirectOnUnallowedHttp3xx_RedirectsEnabled() {
    for (int status = 300; status <= 399; ++status) {
      if (ALLOWED_REDIRECT_STATUSES.contains(status))
        continue;

      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withBody(MOCK_REDIRECT_RESPONSE)));
      byte[] response = createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_REDIRECT_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFollowRedirectOnAllowedHttp3xx_RedirectsEnabled() {
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, wireMock.url(REDIRECT_PATH))));
      wireMock.stubFor(get(REDIRECT_PATH).willReturn(WireMock.aResponse().withStatus(200).withBody(MOCK_RESPONSE)));
      byte[] response = createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFollowMultipleRedirectsOnAllowedHttp3xx_RedirectsEnabled() {
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, wireMock.url(REDIRECT_PATH))));
      wireMock.stubFor(get(REDIRECT_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, wireMock.url(REDIRECT_PATH_2))));
      wireMock.stubFor(get(REDIRECT_PATH_2).willReturn(WireMock.aResponse().withStatus(200).withBody(MOCK_RESPONSE)));
      byte[] response = createDataLoader(2).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMock.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH_2)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFollowLimitedAmountOfRedirectsOnAllowedHttp3xx_RedirectsEnabled() {
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status)
              .withHeader(LOCATION_HEADER, wireMock.url(REDIRECT_PATH)).withBody(MOCK_REDIRECT_RESPONSE)));
      wireMock.stubFor(get(REDIRECT_PATH).willReturn(WireMock.aResponse().withStatus(status)
              .withHeader(LOCATION_HEADER, wireMock.url(REDIRECT_PATH_2)).withBody(MOCK_REDIRECT_RESPONSE_2)));
      byte[] response = createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_REDIRECT_RESPONSE_2, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMock.verify(0, getRequestedFor(urlEqualTo(REDIRECT_PATH_2)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFollowRedirectOnAllowedHttp3xx_RelativeLocation_RedirectsEnabled() {
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, REDIRECT_PATH)));
      wireMock.stubFor(get(REDIRECT_PATH).willReturn(WireMock.aResponse().withStatus(200).withBody(MOCK_RESPONSE)));
      byte[] response = createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMock.resetAll();
    }
  }

  /**
   * This test only works when run separately from the rest of the test classes.
   * The SSL truststore for HttpsURLConnection seems to be configurable only once during a JVM run, but this test
   * requires a different SSL truststore than the rest of the tests that use {@link SimpleHttpGetDataLoader}.
   */
  @Test
  @Disabled("TODO: find a way to run this test together with the rest of the test suite")
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFollowHttpToHttpsRedirectOnAllowedHttp3xx_RedirectsEnabled() {
    System.setProperty("javax.net.ssl.trustStore", "src/test/resources/testFiles/truststores/client-localhost.jks");
    System.setProperty("javax.net.ssl.trustStorePassword", "digidoc4j-password");
    System.setProperty("javax.net.ssl.trustStoreType", "JKS");
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, wireMockHttps.url(REDIRECT_PATH))));
      wireMockHttps.stubFor(get(REDIRECT_PATH).willReturn(WireMock.aResponse().withStatus(200).withBody(MOCK_RESPONSE)));
      byte[] response = createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_RESPONSE, response);
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.verify(0, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMock.resetAll();
      wireMockHttps.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMockHttps.resetAll();
    }
  }

  /**
   * This test only works when run separately from the rest of the test classes.
   * The SSL truststore for HttpsURLConnection seems to be configurable only once during a JVM run, but this test
   * requires a different SSL truststore than the rest of the tests that use {@link SimpleHttpGetDataLoader}.
   */
  @Test
  @Disabled("TODO: find a way to run this test together with the rest of the test suite")
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFollowHttpsToHttpRedirectOnAllowedHttp3xx_RedirectsEnabled() {
    System.setProperty("javax.net.ssl.trustStore", "src/test/resources/testFiles/truststores/client-localhost.jks");
    System.setProperty("javax.net.ssl.trustStorePassword", "digidoc4j-password");
    System.setProperty("javax.net.ssl.trustStoreType", "JKS");
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMockHttps.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, wireMock.url(REDIRECT_PATH))));
      wireMock.stubFor(get(REDIRECT_PATH).willReturn(WireMock.aResponse().withStatus(200).withBody(MOCK_RESPONSE)));
      byte[] response = createDataLoader(1).request(wireMockHttps.url(REQUEST_PATH), true);
      assertResponseForStatus(status, MOCK_RESPONSE, response);
      wireMockHttps.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMockHttps.verify(0, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMockHttps.resetAll();
      wireMock.verify(1, getRequestedFor(urlEqualTo(REDIRECT_PATH)));
      wireMock.resetAll();
    }
  }

  /**
   * This test is meant to cover the protocol change from HTTP to HTTPS by assuming that the requested URL requests at
   * least one redirect, one of which is from HTTP to HTTPS, and returns a valid certificate with CN:
   * {@code EE Certification Centre Root CA}
   */
  @Test
  public void requestShouldFollowRedirectsOfValidCertificate() {
    byte[] response = createDataLoader(3).request("http://www.sk.ee/certs/EE_Certification_Centre_Root_CA.der.crt", true);
    CertificateToken loadedCertificate = DSSUtils.loadCertificate(response);
    assertTrue(
            loadedCertificate.getSubject().getPrincipal().getName().contains("CN=EE Certification Centre Root CA"),
            "Certificate subject principal should contain 'CN=EE Certification Centre Root CA'"
    );
    assertLogInOrder(
            Matchers.matchesPattern("Received HTTP 3[0-9]{2} from 'http://www.sk.ee/certs/EE_Certification_Centre_Root_CA.der.crt', redirecting to 'https://www.sk.ee/certs/EE_Certification_Centre_Root_CA.der.crt'"),
            Matchers.matchesPattern("Received HTTP 3[0-9]{2} from 'https://www.sk.ee/certs/EE_Certification_Centre_Root_CA.der.crt', redirecting to 'https://www.sk.ee/upload/files/EE_Certification_Centre_Root_CA.der.crt'"),
            Matchers.matchesPattern("Reading response of specific size: [0-9]+")
    );
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldNotFollowRedirectOnAllowedHttp3xx_UnsupportedProtocol_RedirectsEnabled() {
    for (int status : ALLOWED_REDIRECT_STATUSES) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status).withHeader(LOCATION_HEADER, "ftp://host:1234/path")));
      try {
        createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
        fail("Should have thrown an exception!");
      } catch (Exception ex) {
        assertEquals("Unsupported protocol: ftp", ex.getMessage());
      }
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  public void requestShouldFailOn404() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(404)));
    try {
      createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      fail("Should have thrown an exception!");
    } catch (Exception ex) {
      assertInstanceOf(FileNotFoundException.class, ex.getCause());
      assertEquals(wireMock.url(REQUEST_PATH), ex.getCause().getMessage());
    }
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
  }

  @Test
  public void requestShouldFailOn410() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(410)));
    try {
      createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
      fail("Should have thrown an exception!");
    } catch (Exception ex) {
      assertInstanceOf(FileNotFoundException.class, ex.getCause());
      assertEquals(wireMock.url(REQUEST_PATH), ex.getCause().getMessage());
    }
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFailOnClientError() {
    for (int status = 400; status <= 499; ++status) {
      if (Arrays.asList(404, 410).contains(status))
        continue;

      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status)));
      try {
        createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
        fail("Should have thrown an exception!");
      } catch (Exception ex) {
        assertEquals(String.format("Failed to read from '%s': Server returned HTTP response code: %d for URL: %s",
                wireMock.url(REQUEST_PATH), status, wireMock.url(REQUEST_PATH)),
                ex.getMessage());
      }
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  public void requestShouldFailOnServerError() {
    for (int status = 500; status <= 599; ++status) {
      wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(status)));
      try {
        createDataLoader(1).request(wireMock.url(REQUEST_PATH), true);
        fail("Should have thrown an exception!");
      } catch (Exception ex) {
        assertEquals(String.format("Failed to read from '%s': Server returned HTTP response code: %d for URL: %s",
                wireMock.url(REQUEST_PATH), status, wireMock.url(REQUEST_PATH)),
                ex.getMessage());
      }
      wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
      wireMock.resetAll();
    }
  }

  @Test
  public void requestShouldFailWhenReadTimeoutIsReached() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.aResponse().withStatus(200).withFixedDelay(1500)));
    SimpleHttpGetDataLoader dataLoader = createDataLoader(0);
    dataLoader.setConnectTimeout(1000);
    dataLoader.setReadTimeout(1000);
    try {
      dataLoader.request(wireMock.url(REQUEST_PATH), true);
      fail("Should have thrown an exception!");
    } catch (Exception ex) {
      assertEquals("Failed to read from '" + wireMock.url(REQUEST_PATH) + "': Read timed out", ex.getMessage());
    }
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH)));
  }

  @Test
  public void requestShouldIncludeSpecificUserAgentHeaderIfSpecified() {
    wireMock.stubFor(get(REQUEST_PATH).willReturn(WireMock.ok()));
    SimpleHttpGetDataLoader dataLoader = new SimpleHttpGetDataLoader();
    dataLoader.setUserAgent("test-user-agent-string");
    dataLoader.request(wireMock.url(REQUEST_PATH), true);
    wireMock.verify(1, getRequestedFor(urlEqualTo(REQUEST_PATH))
            .withHeader("User-Agent", equalTo("test-user-agent-string")));
  }

  private void assertLogInOrder(Matcher... matchers) {
    ArgumentCaptor<ILoggingEvent> argumentCaptor = ArgumentCaptor.forClass(ILoggingEvent.class);
    Mockito.verify(mockedAppender, Mockito.times(matchers.length)).doAppend(argumentCaptor.capture());
    List listOfMessages = argumentCaptor.getAllValues().stream().map(ILoggingEvent::getFormattedMessage).collect(Collectors.toList());
    MatcherAssert.assertThat(listOfMessages, IsIterableContainingInOrder.contains(matchers));
  }

  private static SimpleHttpGetDataLoader createDataLoader(int followRedirects) {
    SimpleHttpGetDataLoader dataLoader = new SimpleHttpGetDataLoader();
    dataLoader.setFollowRedirects(followRedirects);
    return dataLoader;
  }

  private static void assertResponseForStatus(int status, byte[] expectedResponse, byte[] receivedResponse) {
    if (status == HttpURLConnection.HTTP_NOT_MODIFIED) { // 304 returns no body
      assertArrayEquals(new byte[0], receivedResponse);
    } else {
      assertArrayEquals(expectedResponse, receivedResponse);
    }
  }

}
