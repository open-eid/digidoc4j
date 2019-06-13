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
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.ConnectionTimedOutException;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static org.digidoc4j.Configuration.Mode.TEST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class SkTimestampDataLoaderTest extends AbstractTest {

  private static final String MOCK_PROXY_URL = "http://localhost:";

  @Rule
  public WireMockRule instanceRule = new WireMockRule(Options.DYNAMIC_PORT);

  @Test
  public void getServiceType() {
    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    assertEquals(SkTimestampDataLoader.SERVICE_TYPE, dataLoader.getServiceType());
  }

  @Test
  public void getContentType() {
    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    assertEquals(TimestampDataLoader.TIMESTAMP_QUERY_CONTENT_TYPE, dataLoader.getContentType());
  }

  @Test
  public void accessDeniedToOCSPService() {
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().withStatus(403)));

    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
    String serviceUrl = MOCK_PROXY_URL + instanceRule.port() + "/";

    try {
      dataLoader.post(serviceUrl, new byte[] {1});
      fail("Expected to throw ServiceAccessDeniedException");
    } catch (ServiceAccessDeniedException e) {
      assertEquals(SkTimestampDataLoader.SERVICE_TYPE, e.getServiceType());
      assertEquals("Access denied to TSP service <" + serviceUrl + ">", e.getMessage());
    }
  }

  @Test
  public void connectionToTSPServiceTimedOut() {
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().withFixedDelay(200)));

    SkTimestampDataLoader dataLoader = new SkTimestampDataLoader(Configuration.of(TEST));
    dataLoader.setTimeoutSocket(100);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT_TM));
    String serviceUrl = MOCK_PROXY_URL + instanceRule.port() + "/";

    try {
      dataLoader.post(serviceUrl, new byte[] {1});
      fail("Expected to throw ConnectionTimedOutException");
    } catch (ConnectionTimedOutException e) {
      assertEquals(SkTimestampDataLoader.SERVICE_TYPE, e.getServiceType());
      assertEquals("Connection to TSP service <" + serviceUrl + "> timed out", e.getMessage());
    }
  }

  @Test
  public void getTimestampViaSpy() throws Exception {
    instanceRule.stubFor(post("/").willReturn(WireMock.aResponse().proxiedFrom(this.configuration.getTspSource())));
    byte[] tsRequest = new byte[]{48, 57, 2, 1, 1, 48, 49, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32, 2, 91, 64, 111, 35, -23, -19, -46, 57, -80, -63, -80, -74, 100, 72, 97, -47, -17, -35, -62, 102, 52, 116, 73, -10, -120, 115, 62, 2, 87, -29, -21, 1, 1, -1};
    SkDataLoader dataLoader = new SkTimestampDataLoader(this.configuration);
    dataLoader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
    byte[] response = dataLoader.post(MOCK_PROXY_URL, tsRequest);
    Assert.assertNotNull(response);
    TimeStampResponse timeStampResponse = new TimeStampResponse(response);
    Assert.assertEquals(0, timeStampResponse.getStatus());
    timeStampResponse.validate(new TimeStampRequest(tsRequest));
    WireMock.verify(postRequestedFor(urlMatching("/"))
          .withHeader("Content-Type", containing("application/timestamp-query"))
          .withHeader("User-Agent", containing("LIB DigiDoc4j")));
  }
}
