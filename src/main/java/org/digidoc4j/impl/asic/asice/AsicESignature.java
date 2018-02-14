package org.digidoc4j.impl.asic.asice;

import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidator;

/**
 * Created by Andrei on 29.11.2017.
 */
public class AsicESignature extends AsicSignature {

  /**
   * AsicE signature constructor.
   *
   * @param xadesSignature XADES signature
   * @param validator signature validator
   */
  public AsicESignature(XadesSignature xadesSignature, SignatureValidator validator) {
    super(xadesSignature, validator);
  }

}
