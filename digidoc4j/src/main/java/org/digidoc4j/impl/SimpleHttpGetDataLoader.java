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

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

/**
 * A simple data loader that supports HTTP GET methods and redirects with protocol change.
 */
class SimpleHttpGetDataLoader implements DataLoader {

  private static final Logger LOGGER = LoggerFactory.getLogger(SimpleHttpGetDataLoader.class);

  private static final int[] ALLOWED_REDIRECT_STATUSES = {
          HttpURLConnection.HTTP_MOVED_PERM, // 301 Moved Permanently
          HttpURLConnection.HTTP_MOVED_TEMP, // 302 Found (previously Moved Temporarily)
          HttpURLConnection.HTTP_SEE_OTHER, // 303 See Other
          307, // Temporary Redirect
          308, // Permanent Redirect
  };

  private static final String[] ALLOWED_PROTOCOLS = {"http", "https"};
  private static final String REDIRECT_URL_HEADER = "Location";
  private static final String USER_AGENT_HEADER = "User-Agent";
  private static final String REQUEST_METHOD = "GET";

  private String userAgent = null;
  private int followRedirects = 0;
  private int connectTimeout = 2000;
  private int readTimeout = 2000;

  /**
   * Execute a HTTP GET operation.
   * @param url the url to access
   * @return {@code byte} array of obtained data
   */
  @Override
  public byte[] get(String url) {
    return request(url, false);
  }

  /**
   * Operation not supported. Throws {@link NotImplementedException}.
   * @param urlStrings not used
   * @return not used
   */
  @Override
  public DataAndUrl get(List<String> urlStrings) {
    throw new NotImplementedException("Bulk HTTP GET is not supported");
  }

  /**
   * Execute a HTTP GET operation with indication concerning the mandatory nature of the operation.
   * @param url the url to access
   * @param refresh whether the cached data should be refreshed or not
   * @return {@code byte} array of obtained data
   */
  @Override
  public byte[] get(String url, boolean refresh) {
    return request(url, refresh);
  }

  /**
   * Operation not supported. Throws {@link NotImplementedException}.
   * @param url not used
   * @param content not used
   * @return not used
   */
  @Override
  public byte[] post(String url, byte[] content) {
    throw new NotImplementedException("HTTP POST is not supported");
  }

  /**
   * Operation not supported. Throws {@link NotImplementedException}.
   * @param contentType not used
   */
  @Override
  public void setContentType(String contentType) {
    throw new NotImplementedException("Setting the Content-Type is not supported");
  }

  /**
   * Sets the user agent string for User-Agent header.
   * @param userAgent user agent string
   */
  public void setUserAgent(String userAgent) {
    this.userAgent = userAgent;
  }

  /**
   * Gets the the currently set user agent string or null if not specified.
   * @return current user agent string
   */
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Sets the maximum number of redirects to follow. A value larger that 0 enables following redirects.
   * @param followRedirects redirects to follow
   */
  public void setFollowRedirects(int followRedirects) {
    this.followRedirects = followRedirects;
  }

  /**
   * Gets the maximum number of redirects allowed to follow.
   * @return redirects to follow
   */
  public int getFollowRedirects() {
    return followRedirects;
  }

  /**
   * Sets a specified timeout value, in milliseconds, to be used when opening a communications link to the resource referenced.
   * A timeout of zero is interpreted as an infinite timeout.
   * @param connectTimeout timeout value in milliseconds
   */
  public void setConnectTimeout(int connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  /**
   * Gets the currently set connect timeout value, in milliseconds.
   * @return currently set timeout value in milliseconds
   */
  public int getConnectTimeout() {
    return connectTimeout;
  }

  /**
   * Sets the read timeout to a specified timeout, in milliseconds.
   * A non-zero value specifies the timeout when reading from a stream when a connection is established to a resource.
   * A timeout of zero is interpreted as an infinite timeout.
   * @param readTimeout timeout value in milliseconds
   */
  public void setReadTimeout(int readTimeout) {
    this.readTimeout = readTimeout;
  }

  /**
   * Gets the currently set read timeout value, in milliseconds.
   * @return currently set timeout value in milliseconds
   */
  public int getReadTimeout() {
    return readTimeout;
  }

  protected byte[] request(String url, boolean refresh) {
    HttpURLConnection connection = null;
    try {
      connection = openAndConfigureConnection(getHttpUrl(url, Optional.empty()), refresh);
      if (followRedirects > 0) {
        connection = followRedirects(connection, refresh);
      }
      return readFromConnection(connection);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read from '" + url + "': " + e.getMessage(), e);
    } finally {
      if (connection != null) connection.disconnect();
    }
  }

  private HttpURLConnection openAndConfigureConnection(URL url, boolean refresh) throws IOException {
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();

    connection.setDoInput(true);
    connection.setUseCaches(!refresh);
    connection.setRequestMethod(REQUEST_METHOD);
    connection.setInstanceFollowRedirects(false);
    connection.setConnectTimeout(connectTimeout);
    connection.setReadTimeout(readTimeout);

    if (StringUtils.isNotBlank(userAgent)) {
      connection.setRequestProperty(USER_AGENT_HEADER, userAgent);
    }

    connection.connect();

    return connection;
  }

  private HttpURLConnection followRedirects(HttpURLConnection connection, boolean refresh) throws IOException {
    for (int httpStatus, i = 0; i < followRedirects && shouldRedirect(httpStatus = connection.getResponseCode()); ++i) {
      String redirectUrl = connection.getHeaderField(REDIRECT_URL_HEADER);
      if (StringUtils.isBlank(redirectUrl)) {
        LOGGER.warn("Received HTTP {} from '{}', but no redirect URL provided", httpStatus, connection.getURL().toString());
        return connection;
      }

      URL baseUrl = connection.getURL();
      connection.disconnect();

      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Received HTTP {} from '{}', redirecting to '{}'", httpStatus, connection.getURL().toString(), redirectUrl);
      }

      connection = openAndConfigureConnection(getHttpUrl(redirectUrl, Optional.of(baseUrl)), refresh);
    }

    return connection;
  }

  private static URL getHttpUrl(String urlString, Optional<URL> base) {
    URL url;

    try {
      if (base.isPresent()) {
        url = new URL(base.get(), urlString);
      } else {
        url = new URL(urlString);
      }
    } catch (MalformedURLException e) {
      throw new IllegalStateException("Invalid URL: " + urlString, e);
    }

    for (String allowedProtocol : ALLOWED_PROTOCOLS) {
      if (allowedProtocol.equalsIgnoreCase(url.getProtocol())) {
        return url;
      }
    }

    throw new IllegalStateException("Unsupported protocol: " + url.getProtocol());
  }

  private static byte[] readFromConnection(HttpURLConnection connection) throws IOException {
    long contentLength = connection.getContentLengthLong();
    if (contentLength > Integer.MAX_VALUE) {
      throw new IllegalStateException("Unsupported Content-Length: " + contentLength);
    }

    try (InputStream in = connection.getInputStream()) {
      if (contentLength >= 0L) {
        LOGGER.debug("Reading response of specific size: {}", contentLength);
        return readFromInputStream(in, (int) contentLength);
      } else {
        LOGGER.debug("Reading response of unspecified size");
        return Utils.toByteArray(in);
      }
    }
  }

  private static byte[] readFromInputStream(InputStream in, int length) throws IOException {
    byte[] bytes = new byte[length];
    int read = in.read(bytes, 0, length);

    if (read == length) {
      return bytes;
    } else {
      throw new EOFException("Unexpected end of stream");
    }
  }

  private static boolean shouldRedirect(int httpStatus) {
    for (int allowedRedirectStatus : ALLOWED_REDIRECT_STATUSES) {
      if (httpStatus == allowedRedirectStatus) return true;
    }
    return false;
  }

}
