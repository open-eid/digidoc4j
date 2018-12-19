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

import java.net.MalformedURLException;
import java.net.URL;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Supported algorithms
 */
public enum DigestAlgorithm {
  SHA1("http://www.w3.org/2000/09/xmldsig#sha1",
      new byte[]{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}),
  SHA224("http://www.w3.org/2001/04/xmldsig-more#sha224",
      new byte[]{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}),
  SHA256("http://www.w3.org/2001/04/xmlenc#sha256",
      new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}),
  SHA384("http://www.w3.org/2001/04/xmldsig-more#sha384",
      new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}),
  SHA512("http://www.w3.org/2001/04/xmlenc#sha512",
      new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40});

  private URL uri;
  private byte[] digestInfoPrefix;

  DigestAlgorithm(String uri, byte[] digestInfoPrefix) {
    try {
      this.uri = new URL(uri);
      this.digestInfoPrefix = digestInfoPrefix;
    } catch (MalformedURLException e) {
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Get uri
   *
   * @return uri
   */
  public URL uri() {
    return uri;
  }

  public byte[] digestInfoPrefix() {
    return digestInfoPrefix;
  }

  public eu.europa.esig.dss.DigestAlgorithm getDssDigestAlgorithm() {
    return eu.europa.esig.dss.DigestAlgorithm.forXML(uri.toString());
  }

  /**
   * Get uri string
   *
   * @return uri
   */
  public String toString() {
    return uri.toString();
  }

  /**
   * Find DigestAlgorithm by algorithm string.
   *
   * @param algorithm
   * @return DigestAlgorithm.
   */
  public static DigestAlgorithm findByAlgorithm(String algorithm) {
    for (DigestAlgorithm digestAlgorithm : values()) {
      if (digestAlgorithm.name().equals(algorithm)) {
        return digestAlgorithm;
      }
    }
    return null;
  }

}
