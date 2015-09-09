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

public abstract class DataToSign implements Serializable {

  private byte[] digestToSign;
  private SignatureParameters signatureParameters;

  protected DataToSign(byte[] digestToSign, SignatureParameters signatureParameters) {
    this.digestToSign = digestToSign;
    this.signatureParameters = signatureParameters;
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

  public abstract Signature finalize(byte[] signatureValue);
}
