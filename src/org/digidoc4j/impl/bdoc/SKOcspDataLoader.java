/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.util.EntityUtils;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;

public class SKOcspDataLoader extends OCSPDataLoader {

  private static final Logger logger = LoggerFactory.getLogger(SKOcspDataLoader.class);
  private String userAgent;

  public SKOcspDataLoader() {
    userAgent = Helper.createBDocUserAgent();
  }

  @Override
  public byte[] post(final String url, final byte[] content) throws DSSException {
    logger.info("Getting OCSP response from " + url);

    HttpPost httpRequest = null;
    HttpResponse httpResponse = null;

    try {
      final URI uri = URI.create(url.trim());
      httpRequest = new HttpPost(uri);
      httpRequest.setHeader("User-Agent", userAgent);

      // The length for the InputStreamEntity is needed, because some receivers (on the other side) need this information.
      // To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
      // This is because, it may not be possible to reset the stream (= go to position 0).
      // So, the solution is to cache temporarily the complete content data (as we do not expect much here) in a byte-array.
      final ByteArrayInputStream bis = new ByteArrayInputStream(content);

      final HttpEntity httpEntity = new InputStreamEntity(bis, content.length);
      final HttpEntity requestEntity = new BufferedHttpEntity(httpEntity);
      httpRequest.setEntity(requestEntity);
      if (contentType != null) {
        httpRequest.setHeader(CONTENT_TYPE, contentType);
      }

      httpResponse = getHttpResponse(httpRequest, url);

      final byte[] returnedBytes = readHttpResponse(url, httpResponse);
      return returnedBytes;
    } catch (IOException e) {
      throw new DSSException(e);
    } finally {
      if (httpRequest != null) {
        httpRequest.releaseConnection();
      }
      if (httpResponse != null) {
        EntityUtils.consumeQuietly(httpResponse.getEntity());
      }
    }
  }

  public void setUserAgentSignatureProfile(SignatureProfile signatureProfile) {
    userAgent = Helper.createBDocUserAgent(signatureProfile);
  }
}
