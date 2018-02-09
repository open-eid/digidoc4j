package org.digidoc4j.impl.asic.asics;

import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidator;

/**
 * Created by Andrei on 29.11.2017.
 */
public class AsicSSignature extends AsicSignature {

  /**
   * AsicS signature constructor.
   *
   * @param xadesSignature XADES signature
   * @param validator signature validator
   */
  public AsicSSignature(XadesSignature xadesSignature, SignatureValidator validator) {
    super(xadesSignature, validator);
  }
}
