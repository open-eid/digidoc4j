/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import eu.europa.esig.dss.utils.Utils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;

/**
 * Data loader implementation for SK ID Solutions AS
 */
public class SkDataLoader extends CommonsDataLoader {

  private static final String TIMESTAMP_CONTENT_TYPE = "application/timestamp-query";
  private final Logger log = LoggerFactory.getLogger(SkDataLoader.class);
  private String userAgent;

  protected SkDataLoader(Configuration configuration) {
    DataLoaderDecorator.decorateWithProxySettings(this, configuration);
    DataLoaderDecorator.decorateWithSslSettings(this, configuration);
  }

  /**
   * Content type "application/ocsp-request"
   *
   * @param configuration configuration context
   * @return DataLoader
   */
  public static SkDataLoader ocsp(Configuration configuration) {
    SkDataLoader dataLoader = new SkDataLoader(configuration);
    dataLoader.setContentType(OCSPDataLoader.OCSP_CONTENT_TYPE);
    return dataLoader;
  }

  /**
   * Content type "application/timestamp-query"
   *
   * @param configuration configuration context
   * @return
   */
  public static SkDataLoader timestamp(Configuration configuration) {
    SkDataLoader dataLoader = new SkDataLoader(configuration);
    dataLoader.setContentType(SkDataLoader.TIMESTAMP_CONTENT_TYPE);
    return dataLoader;
  }

  @Override
  public byte[] post(final String url, final byte[] content) throws DSSException {
    if (StringUtils.isBlank(url)) {
      throw new TechnicalException("SK endpoint url is unset");
    }
    this.log.debug("Getting OCSP response from <{}>", url);
    if (StringUtils.isBlank(this.userAgent)) {
      throw new TechnicalException("Header <User-Agent> is unset");
    }
    HttpPost httpRequest = null;
    CloseableHttpResponse httpResponse = null;
    CloseableHttpClient client = null;
    try {
      final URI uri = URI.create(url.trim());
      httpRequest = new HttpPost(uri);
      httpRequest.setHeader("User-Agent", this.userAgent);
      ByteArrayInputStream bis = new ByteArrayInputStream(content);
      HttpEntity httpEntity = new InputStreamEntity(bis, content.length);
      HttpEntity requestEntity = new BufferedHttpEntity(httpEntity);
      httpRequest.setEntity(requestEntity);
      if (StringUtils.isNotBlank(this.contentType)) {
        httpRequest.setHeader(CONTENT_TYPE, this.contentType);
      }
      client = getHttpClient(url);
      httpResponse = this.getHttpResponse(client, httpRequest);
      return readHttpResponse(httpResponse);
    } catch (IOException e) {
      throw new DSSException("Unable to process GET call for url '" + url + "'", e);
    } finally {
      try {
        if (httpRequest != null) {
          httpRequest.releaseConnection();
        }
        if (httpResponse != null) {
          EntityUtils.consumeQuietly(httpResponse.getEntity());
        }
      } finally {
        Utils.closeQuietly(client);
      }
    }
  }

  /*
   * ACCESSORS
   */

  public void setUserAgent(String userAgent) {
    this.userAgent = userAgent;
  }

  public String getUserAgent() {
    return userAgent;
  }

}
