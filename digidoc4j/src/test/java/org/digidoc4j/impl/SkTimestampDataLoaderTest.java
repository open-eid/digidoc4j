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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.ServiceType;
import org.digidoc4j.exceptions.ConnectionTimedOutException;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static org.digidoc4j.Configuration.Mode.TEST;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SkTimestampDataLoaderTest extends AbstractTest {

  private static final String MOCK_PROXY_URL = "http://localhost:";

  @RegisterExtension
  static WireMockExtension wireMockServer =
          WireMockExtension.newInstance()
                  .options(WireMockConfiguration.options().dynamicPort())
                  .build();

  @Test
  void getServiceType() {
    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    assertSame(ServiceType.TSP, dataLoader.getServiceType());
  }

  @Test
  void getContentType() {
    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    assertEquals(SkTimestampDataLoader.TIMESTAMP_QUERY_CONTENT_TYPE, dataLoader.getContentType());
  }

  @Test
  void successfulResponseFromTSPService() {
    wireMockServer.stubFor(post("/").withHeader("User-Agent", equalTo(USER_AGENT_STRING))
            .willReturn(WireMock.aResponse().withStatus(200).withBody(new byte[] {0, 1, 2, 3})));
    ServiceAccessListener listener = Mockito.mock(ServiceAccessListener.class);

    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    dataLoader.setUserAgent(USER_AGENT_STRING);
    String serviceUrl = MOCK_PROXY_URL + wireMockServer.getPort() + "/";

    try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
      byte[] response = dataLoader.post(serviceUrl, new byte[] {1});
      assertArrayEquals(new byte[] {0, 1, 2, 3}, response);
    }

    ServiceAccessEvent capturedEvent = verifyAndCaptureServiceAccessEvent(listener);
    assertEquals(MOCK_PROXY_URL + wireMockServer.getPort() + "/", capturedEvent.getServiceUrl());
    assertEquals(ServiceType.TSP, capturedEvent.getServiceType());
    assertTrue(capturedEvent.isSuccess());
  }

  @Test
  void accessDeniedToTSPService() {
    wireMockServer.stubFor(post("/").withHeader("User-Agent", equalTo(USER_AGENT_STRING))
            .willReturn(WireMock.aResponse().withStatus(403)));
    ServiceAccessListener listener = Mockito.mock(ServiceAccessListener.class);

    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    dataLoader.setUserAgent(USER_AGENT_STRING);
    String serviceUrl = MOCK_PROXY_URL + wireMockServer.getPort() + "/";

    try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
      dataLoader.post(serviceUrl, new byte[] {1});
      fail("Expected to throw ServiceAccessDeniedException");
    } catch (ServiceAccessDeniedException e) {
      assertSame(ServiceType.TSP, e.getServiceType());
      assertEquals("Access denied to TSP service <" + serviceUrl + ">", e.getMessage());
    }

    ServiceAccessEvent capturedEvent = verifyAndCaptureServiceAccessEvent(listener);
    assertEquals(MOCK_PROXY_URL + wireMockServer.getPort() + "/", capturedEvent.getServiceUrl());
    assertEquals(ServiceType.TSP, capturedEvent.getServiceType());
    assertFalse(capturedEvent.isSuccess());
  }

  @Test
  void connectionToTSPServiceTimedOut() {
    wireMockServer.stubFor(post("/").withHeader("User-Agent", equalTo(USER_AGENT_STRING))
            .willReturn(WireMock.aResponse().withFixedDelay(200)));
    ServiceAccessListener listener = Mockito.mock(ServiceAccessListener.class);

    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    dataLoader.setTimeoutResponse(100);
    dataLoader.setUserAgent(USER_AGENT_STRING);
    String serviceUrl = MOCK_PROXY_URL + wireMockServer.getPort() + "/";

    try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
      dataLoader.post(serviceUrl, new byte[] {1});
      fail("Expected to throw ConnectionTimedOutException");
    } catch (ConnectionTimedOutException e) {
      assertSame(ServiceType.TSP, e.getServiceType());
      assertEquals("Connection to TSP service <" + serviceUrl + "> timed out", e.getMessage());
    }

    ServiceAccessEvent capturedEvent = verifyAndCaptureServiceAccessEvent(listener);
    assertEquals(MOCK_PROXY_URL + wireMockServer.getPort() + "/", capturedEvent.getServiceUrl());
    assertEquals(ServiceType.TSP, capturedEvent.getServiceType());
    assertFalse(capturedEvent.isSuccess());
  }

  @Test
  void getTimestampViaSpy() throws Exception {
    Configuration configuration = Configuration.of(TEST);
    wireMockServer.stubFor(post("/").willReturn(WireMock.aResponse().proxiedFrom(configuration.getTspSource())));
    byte[] tsRequest = new byte[]{48, 57, 2, 1, 1, 48, 49, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32, 2, 91, 64, 111, 35, -23, -19, -46, 57, -80, -63, -80, -74, 100, 72, 97, -47, -17, -35, -62, 102, 52, 116, 73, -10, -120, 115, 62, 2, 87, -29, -21, 1, 1, -1};
    SkDataLoader dataLoader = new SkTimestampDataLoader(configuration);
    dataLoader.setUserAgent(USER_AGENT_STRING);
    String serviceUrl = MOCK_PROXY_URL + wireMockServer.getPort() + "/";
    byte[] response = dataLoader.post(serviceUrl, tsRequest);
    assertNotNull(response);
    TimeStampResponse timeStampResponse = new TimeStampResponse(response);
    assertEquals(0, timeStampResponse.getStatus());
    timeStampResponse.validate(new TimeStampRequest(tsRequest));
    wireMockServer.verify(postRequestedFor(urlMatching("/"))
          .withHeader("Content-Type", containing("application/timestamp-query"))
          .withHeader("User-Agent", containing(USER_AGENT_STRING)));
  }

  private static ServiceAccessEvent verifyAndCaptureServiceAccessEvent(ServiceAccessListener mockedListener) {
    ArgumentCaptor<ServiceAccessEvent> argumentCaptor = ArgumentCaptor.forClass(ServiceAccessEvent.class);
    Mockito.verify(mockedListener, Mockito.times(1)).accept(argumentCaptor.capture());
    Mockito.verifyNoMoreInteractions(mockedListener);
    return argumentCaptor.getValue();
  }
}
