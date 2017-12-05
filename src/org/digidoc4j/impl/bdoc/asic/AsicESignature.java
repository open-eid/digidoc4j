package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.validation.SignatureValidator;

/**
 * Created by Andrei on 29.11.2017.
 */
public class AsicESignature extends AsicSignature {

  /**
   * AsicE signature constructor.
   *
   * @param xadesSignature
   * @param validator
   */
  public AsicESignature(XadesSignature xadesSignature, SignatureValidator validator) {
    super(xadesSignature, validator);
  }
}
