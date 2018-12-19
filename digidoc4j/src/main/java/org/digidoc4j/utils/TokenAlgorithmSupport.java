/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.utils;

import java.security.cert.X509Certificate;

import org.digidoc4j.DigestAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.digidoc4j.ddoc.factory.DigiDocGenFactory;

public class TokenAlgorithmSupport {

  private final static Logger logger = LoggerFactory.getLogger(TokenAlgorithmSupport.class);

  public static DigestAlgorithm determineSignatureDigestAlgorithm(X509Certificate certificate) {
    if (DigiDocGenFactory.isPre2011IdCard(certificate)) {
      logger.debug("The certificate belongs to a pre 2011 Estonian ID card supporting SHA-224");
      return DigestAlgorithm.SHA224;
    }
    return DigestAlgorithm.SHA256;
  }
}