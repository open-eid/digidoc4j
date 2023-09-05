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

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.impl.asic.AsicSignature;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;

import java.util.List;

/**
 * ASiCS signature finalizer for datafiles signing process.
 */
final class AsicSSignatureFinalizer extends AsicSignatureFinalizer {

  AsicSSignatureFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration) {
    super(dataFilesToSign, signatureParameters, configuration);
  }

  @Override
  protected AsicSignature asAsicSignature(XadesSignatureWrapper signatureWrapper) {
    return new AsicSSignatureOpener(configuration).open(signatureWrapper);
  }

  @Override
  protected void validateSignatureCompatibility() {
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureParameters.getSignatureProfile())) {
      throw new IllegalSignatureProfileException(String.format(
              "Cannot create BDoc specific (%s) signature",
              signatureParameters.getSignatureProfile()
      ));
    }
  }

}
