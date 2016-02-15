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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;

public class SKTimestampDataLoader extends NativeHTTPDataLoader {

  private static final Logger logger = LoggerFactory.getLogger(SKTimestampDataLoader.class);
  private String userAgent;

  public SKTimestampDataLoader() {
    userAgent = Helper.createBDocUserAgent();
  }

  @Override
  public byte[] post(String url, byte[] content) {
    logger.info("Getting timestamp from " + url);
    OutputStream out = null;
    InputStream inputStream = null;
    byte[] result = null;
    try {
      URLConnection connection = new URL(url).openConnection();

      connection.setDoInput(true);
      connection.setDoOutput(true);
      connection.setUseCaches(false);

      connection.setRequestProperty("Content-Type", "application/timestamp-query");
      connection.setRequestProperty("Content-Transfer-Encoding", "binary");
      connection.setRequestProperty("User-Agent", userAgent);

      out = connection.getOutputStream();
      IOUtils.write(content, out);
      inputStream = connection.getInputStream();
      result = IOUtils.toByteArray(inputStream);
    } catch (IOException e) {
      throw new DSSException("An error occured while HTTP POST for url '" + url + "' : " + e.getMessage(), e);
    } finally {
      IOUtils.closeQuietly(out);
      IOUtils.closeQuietly(inputStream);
    }
    return result;
  }

  public void setUserAgentSignatureProfile(SignatureLevel signatureLevel) {
    userAgent = Helper.createBDocUserAgent(signatureLevel);
  }
}
