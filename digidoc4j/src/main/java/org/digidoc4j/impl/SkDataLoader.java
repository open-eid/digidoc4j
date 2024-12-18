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

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.BufferedHttpEntity;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.digidoc4j.Configuration;
import org.digidoc4j.ServiceType;
import org.digidoc4j.exceptions.ConnectionTimedOutException;
import org.digidoc4j.exceptions.NetworkException;
import org.digidoc4j.exceptions.ServiceAccessDeniedException;
import org.digidoc4j.exceptions.ServiceUnreachableException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Data loader implementation for SK ID Solutions AS
 */
public abstract class SkDataLoader extends CommonsDataLoader {

  protected static final Logger LOGGER = LoggerFactory.getLogger(SkDataLoader.class);
  private String userAgent;

  protected SkDataLoader() {}

  protected SkDataLoader(Configuration configuration) {
    DataLoaderDecorator.decorateWithProxySettings(this, configuration);
    DataLoaderDecorator.decorateWithSslSettings(this, configuration);
  }

  @Override
  public byte[] post(final String url, final byte[] content) {
    if (StringUtils.isBlank(url)) {
      throw new TechnicalException("SK endpoint url is unset");
    }
    LOGGER.debug("Getting {} response from <{}>", getServiceType().name(), url);
    if (StringUtils.isBlank(this.userAgent)) {
      throw new TechnicalException("Header <User-Agent> is unset");
    }

    HttpPost httpRequest = null;
    CloseableHttpClient client = null;
    try {
      final URI uri = URI.create(url.trim());
      httpRequest = new HttpPost(uri);
      httpRequest.setHeader("User-Agent", this.userAgent);

      final ByteArrayInputStream bis = new ByteArrayInputStream(content);
      final HttpEntity httpEntity = new InputStreamEntity(bis, content.length, null);
      final HttpEntity requestEntity = new BufferedHttpEntity(httpEntity);
      httpRequest.setEntity(requestEntity);

      if (StringUtils.isNotBlank(this.contentType)) {
        httpRequest.setHeader("Content-Type", this.contentType);
      }

      client = getHttpClient(url);

      final HttpHost targetHost = getHttpHost(httpRequest);
      final HttpContext localContext = getHttpContext(targetHost);
      final HttpClientResponseHandler<byte[]> responseHandler = getHttpClientResponseHandler();
      byte[] responseBytes = client.execute(targetHost, httpRequest, localContext, response -> {
        validateHttpResponse(response, url);
        return responseHandler.handleResponse(response);
      });

      publishExternalServiceAccessEvent(url, true);

      return responseBytes;
    } catch (UnknownHostException e) {
      publishExternalServiceAccessEvent(url, false);
      throw new ServiceUnreachableException(url, getServiceType());
    } catch (InterruptedIOException e) {
      publishExternalServiceAccessEvent(url, false);
      throw new ConnectionTimedOutException(url, getServiceType());
    } catch (NetworkException e) {
      publishExternalServiceAccessEvent(url, false);
      throw e;
    } catch (Exception e) {
      publishExternalServiceAccessEvent(url, false);
      throw new NetworkException("Unable to process <" + getServiceType() + "> POST call for service <" + url + ">", url, getServiceType(), e);
    } finally {
      closeQuietly(httpRequest, client);
    }
  }

  private void validateHttpResponse(ClassicHttpResponse httpResponse, String url) {
    if (httpResponse.getCode() == HttpStatus.SC_FORBIDDEN) {
      throw new ServiceAccessDeniedException(url, getServiceType());
    }
  }

  private void publishExternalServiceAccessEvent(final String url, final boolean success) {
    ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(() -> {
      final ServiceType serviceType = getServiceType();
      return new ServiceAccessEvent(url, serviceType, success);
    });
  }

  protected abstract ServiceType getServiceType();

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
