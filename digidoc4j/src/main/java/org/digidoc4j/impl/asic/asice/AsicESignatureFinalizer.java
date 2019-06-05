/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asice;

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;

import java.util.List;

public class AsicESignatureFinalizer extends AsicSignatureFinalizer {

  public AsicESignatureFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration) {
    super(dataFilesToSign, signatureParameters, configuration);
  }

  @Override
  protected void setSignaturePolicy() {
    // Do nothing
  }

  @Override
  protected void validateSignatureCompatibilityWithContainer() {
    super.validateSignatureCompatibilityWithContainer();
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile())) {
      throw new IllegalSignatureProfileException(
              "Cannot add BDoc specific (" + signatureParameters.getSignatureProfile() + ") signature to ASiCE container");
    }
  }
}
