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

import java.io.Serializable;

import org.digidoc4j.impl.SignatureFinalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DataToSign implements Serializable {

  private final static Logger logger = LoggerFactory.getLogger(DataToSign.class);
  private byte[] digestToSign;
  private SignatureParameters signatureParameters;
  private SignatureFinalizer signatureFinalizer;

  public DataToSign(byte[] digestToSign, SignatureParameters signatureParameters, SignatureFinalizer signatureFinalizer) {
    this.digestToSign = digestToSign;
    this.signatureParameters = signatureParameters;
    this.signatureFinalizer = signatureFinalizer;
  }

  public SignatureParameters getSignatureParameters() {
    return signatureParameters;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    return signatureParameters.getDigestAlgorithm();
  }

  public byte[] getDigestToSign() {
    return digestToSign;
  }

  public Signature finalize(byte[] signatureValue) {
    logger.debug("Finalizing signature");
    return signatureFinalizer.finalizeSignature(signatureValue);
  }
}
