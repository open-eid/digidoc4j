package org.digidoc4j.impl.asic.asice;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.impl.asic.AsicSignatureBuilder;

/**
 * Created by Andrei on 29.11.2017.
 */
public class AsicESignatureBuilder extends AsicSignatureBuilder {

  @Override
  protected void validateSignatureCompatibilityWithContainer() {
    super.validateSignatureCompatibilityWithContainer();
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile()) && isAsicEContainer()) {
      throw new IllegalSignatureProfileException(
              "Cannot add BDoc specific (" + signatureParameters.getSignatureProfile() + ") signature to ASiCE container");
    }
  }

  private boolean isAsicEContainer() {
    return container instanceof AsicEContainer && StringUtils.equals(Container.DocumentType.ASICE.name(), container.getType());
  }
}
