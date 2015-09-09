package org.digidoc4j.impl.bdoc;

import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.AsicFacade;

public class BDocDataToSign extends DataToSign {

  private AsicFacade asicFacade;

  public BDocDataToSign(byte[] digestToSign, SignatureParameters signatureParameters, AsicFacade asicFacade) {
    super(digestToSign, signatureParameters);
    this.asicFacade = asicFacade;
  }

  @Override
  public Signature finalize(byte[] signatureValue) {
    return asicFacade.signRaw(signatureValue);
  }
}
