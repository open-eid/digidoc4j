package org.digidoc4j;

import org.digidoc4j.exceptions.DigiDoc4JException;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Supported algorithms
 */
public enum DigestAlgorithm {
  SHA1("http://www.w3.org/2000/09/xmldsig#sha1"),
  SHA224("http://www.w3.org/2001/04/xmldsig-more#sha224"),
  SHA256("http://www.w3.org/2001/04/xmlenc#sha256"),
  SHA384("http://www.w3.org/2001/04/xmldsig-more#sha384"),
  SHA512("http://www.w3.org/2001/04/xmlenc#sha512");

  private URL uri;

  private DigestAlgorithm(String uri) {
    try {
      this.uri = new URL(uri);
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
}
