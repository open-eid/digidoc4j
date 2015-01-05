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

import eu.europa.ec.markt.dss.DSSUtils;
import org.slf4j.Logger;

import java.io.Serializable;

import static eu.europa.ec.markt.dss.DigestAlgorithm.forXML;

public class SignedInfo implements Serializable {
  Logger logger = org.slf4j.LoggerFactory.getLogger(SignedInfo.class);
  private byte[] digest;
  private DigestAlgorithm digestAlgorithm;

  @SuppressWarnings("UnusedDeclaration")
  private SignedInfo() {}

  public SignedInfo(byte[] signedInfo, DigestAlgorithm digestAlgorithm) {
    logger.debug("");
    this.digestAlgorithm = digestAlgorithm;
    digest = DSSUtils.digest(forXML(digestAlgorithm.toString()), signedInfo);
  }

  public byte[] getDigest() {
    logger.debug("");
    return digest;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    logger.debug("");
    return digestAlgorithm;
  }
}
