package org.digidoc4j.impl.ddoc;

import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.DDocFacade;

public class DDocDataToSign extends DataToSign {

  private DDocFacade jDigiDocFacade;

  public DDocDataToSign(byte[] digestToSign, SignatureParameters signatureParameters, DDocFacade jDigiDocFacade) {
    super(digestToSign, signatureParameters);
    this.jDigiDocFacade = jDigiDocFacade;
  }

  @Override
  public Signature finalize(byte[] signatureValue) {
    return jDigiDocFacade.signRaw(signatureValue);
  }
}
