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
import com.github.tomakehurst.wiremock.core.Options;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.ServiceType;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.ConnectionTimedOutException;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
import org.digidoc4j.utils.Helper;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static org.digidoc4j.Configuration.Mode.TEST;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

public class SkOCSPDataLoaderTest extends AbstractTest {

  private static final String MOCK_PROXY_URL = "http://localhost:";

  @Rule
  public WireMockRule instanceRule = new WireMockRule(Options.DYNAMIC_PORT);

  @After
  public void tearDown() {
    WireMock.reset();
  }

  @Test
  public void getServiceType() {
    SkOCSPDataLoader dataLoader = new SkOCSPDataLoader(Configuration.of(TEST));
    assertSame(ServiceType.OCSP, dataLoader.getServiceType());
  }

  @Test
  public void getContentType() {
    SkOCSPDataLoader dataLoader = new SkOCSPDataLoader(Configuration.of(TEST));
    assertEquals(OCSPDataLoader.OCSP_CONTENT_TYPE, dataLoader.getContentType());
  }

  @Test
  public void successfulResponseFromOCSPService() {
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().withStatus(200).withBody(new byte[] {0, 1, 2, 3})));
    ServiceAccessListener listener = Mockito.mock(ServiceAccessListener.class);

    SkOCSPDataLoader dataLoader = new SkOCSPDataLoader(Configuration.of(TEST));
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT_TM));
    String serviceUrl = MOCK_PROXY_URL + instanceRule.port() + "/";

    try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
      byte[] response = dataLoader.post(serviceUrl, new byte[] {1});
      assertArrayEquals(new byte[] {0, 1, 2, 3}, response);
    }

    ArgumentCaptor<ServiceAccessEvent> argumentCaptor = ArgumentCaptor.forClass(ServiceAccessEvent.class);
    Mockito.verify(listener, Mockito.times(1)).accept(argumentCaptor.capture());
    Mockito.verifyNoMoreInteractions(listener);

    ServiceAccessEvent capturedEvent = argumentCaptor.getValue();
    assertEquals(MOCK_PROXY_URL + instanceRule.port() + "/", capturedEvent.getServiceUrl());
    assertEquals(ServiceType.OCSP, capturedEvent.getServiceType());
  }

  @Test
  public void accessDeniedToOCSPService() {
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().withStatus(403)));
    ServiceAccessListener listener = Mockito.mock(ServiceAccessListener.class);

    SkOCSPDataLoader dataLoader = new SkOCSPDataLoader(Configuration.of(TEST));
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT_TM));
    String serviceUrl = MOCK_PROXY_URL + instanceRule.port() + "/";

    try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
      dataLoader.post(serviceUrl, new byte[] {1});
      fail("Expected to throw ServiceAccessDeniedException");
    } catch (ServiceAccessDeniedException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals("Access denied to OCSP service <" + serviceUrl + ">", e.getMessage());
    }

    Mockito.verifyZeroInteractions(listener);
  }

  @Test
  public void connectionToOCSPServiceTimedOut() {
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().withFixedDelay(200)));
    ServiceAccessListener listener = Mockito.mock(ServiceAccessListener.class);

    SkOCSPDataLoader dataLoader = new SkOCSPDataLoader(Configuration.of(TEST));
    dataLoader.setTimeoutSocket(100);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT_TM));
    String serviceUrl = MOCK_PROXY_URL + instanceRule.port() + "/";

    try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
      dataLoader.post(serviceUrl, new byte[] {1});
      fail("Expected to throw ConnectionTimedOutException");
    } catch (ConnectionTimedOutException e) {
      assertSame(ServiceType.OCSP, e.getServiceType());
      assertEquals("Connection to OCSP service <" + serviceUrl + "> timed out", e.getMessage());
    }

    Mockito.verifyZeroInteractions(listener);
  }

  @Test
  public void getOcspViaSpy() throws Exception {
    Configuration configuration = Configuration.of(TEST);
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().proxiedFrom(configuration.getOcspSource())));
    byte[] ocspRequest = new byte[]{48, 120, 48, 118, 48, 77, 48, 75, 48, 73, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, -20, -37, 96, 16, 51, -48, 76, 118, -7, -123, -78, 28, -40, 58, -45, -98, 2, -101, -109, 49, 4, 20, 73, -64, -14, 68, 57, 101, -43, -101, 70, 59, 13, 56, 96, -125, -79, -42, 45, 40, -122, -90, 2, 16, 83, 11, -28, 27, -68, 89, 124, 68, 87, 14, 43, 124, 19, -68, -6, 12, -94, 37, 48, 35, 48, 33, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 20, -55, 25, 66, -2, -90, 61, 30, -49, 20, -82, 91, 49, -4, -52, -64, 23, 106, 12, -114, 67};
    SkDataLoader dataLoader = new SkOCSPDataLoader(configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
    String serviceUrl = MOCK_PROXY_URL + instanceRule.port() + "/";
    byte[] response = dataLoader.post(serviceUrl, ocspRequest);
    OCSPResp ocspResp = new OCSPResp(response);
    Assert.assertNotNull(ocspResp.getResponseObject());
    WireMock.verify(postRequestedFor(urlMatching("/"))
          .withHeader("Content-Type", containing("application/ocsp-request"))
          .withHeader("User-Agent", containing("LIB DigiDoc4j")));
  }
}
