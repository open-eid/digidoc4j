/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidatorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Base class for converting XAdES signature to ASiC signature.
 */
public abstract class AsicXadesSignatureOpener implements AsicSignatureOpener {

  private final static Logger LOGGER = LoggerFactory.getLogger(AsicXadesSignatureOpener.class);

  protected final Configuration configuration;

  /**
   * Creates an instance of ASiC signature opener
   *
   * @param configuration configuration
   */
  protected AsicXadesSignatureOpener(Configuration configuration) {
    this.configuration = Objects.requireNonNull(configuration);
  }

  /**
   * XAdES signature wrapper opening method.
   * @param signatureWrapper wrapper containing signature document and its XAdES signature
   * @return ASiC signature
   */
  @Override
  public AsicSignature open(XadesSignatureWrapper signatureWrapper) {
    LOGGER.debug("Opening XAdES signature");
    XadesSignatureValidator xadesValidator = createSignatureValidator(signatureWrapper.getSignature());
    AsicSignature asicSignature = createAsicSignature(signatureWrapper.getSignature(), xadesValidator);
    asicSignature.setSignatureDocument(signatureWrapper.getSignatureDocument());
    asicSignature.setConfiguration(configuration);
    return asicSignature;
  }

  protected abstract AsicSignature createAsicSignature(XadesSignature xadesSignature, XadesSignatureValidator xadesValidator);

  private XadesSignatureValidator createSignatureValidator(XadesSignature signature) {
    XadesSignatureValidatorFactory validatorFactory = new XadesSignatureValidatorFactory();
    validatorFactory.setConfiguration(configuration);
    validatorFactory.setSignature(signature);
    return validatorFactory.create();
  }

}
