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

import static eu.europa.esig.dss.DigestAlgorithm.forXML;

import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;

public class SignedInfo implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(SignedInfo.class);

  private byte[] digestToSign;
  private SignatureParameters signatureParameters;

  public SignedInfo() {
  }

  public SignedInfo(byte[] dataToDigest, SignatureParameters signatureParameters) {
    DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();
    digestToSign = DSSUtils.digest(forXML(digestAlgorithm.toString()), dataToDigest);
    this.signatureParameters = signatureParameters;
  }

  public byte[] getDigest() {
    logger.debug("");
    return getDigestToSign();
  }

  public byte[] getDigestToSign() {
    return digestToSign;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    logger.debug("");
    return signatureParameters.getDigestAlgorithm();
  }

  public SignatureParameters getSignatureParameters() {
    return signatureParameters;
  }
}
