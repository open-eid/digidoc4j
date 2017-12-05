package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidator;

/**
 * Created by Andrei on 29.11.2017.
 */
public class AsicSSignature extends AsicSignature {

  /**
   * AsicS signature constructor.
   *
   * @param xadesSignature
   * @param validator
   */
  public AsicSSignature(XadesSignature xadesSignature, SignatureValidator validator) {
    super(xadesSignature, validator);
  }
}
