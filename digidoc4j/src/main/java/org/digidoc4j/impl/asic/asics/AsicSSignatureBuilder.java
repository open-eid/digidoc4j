/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.AsicSignatureBuilder;

public class AsicSSignatureBuilder extends AsicSignatureBuilder {

  @Override
  protected SignatureFinalizer createSignatureFinalizer() {
    return new AsicSSignatureFinalizer(container.getDataFiles(), signatureParameters, getConfiguration());
  }

  @Override
  protected void validateSignatureCompatibilityWithContainer() {
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile()) && isAsicSContainer()) {
      throw new IllegalSignatureProfileException(
              "Cannot add BDoc specific (" + signatureParameters.getSignatureProfile() + ") signature to ASiCS container");
    }
  }

  private boolean isAsicSContainer() {
    return container instanceof AsicSContainer && StringUtils.equals(Container.DocumentType.ASICS.name(), container.getType());
  }

}
