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
