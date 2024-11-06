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
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.AsicContainerValidator;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignature;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * ASiC-S container validator
 */
public class AsicSContainerValidator extends AsicContainerValidator {

  /**
   * @param configuration configuration
   */
  public AsicSContainerValidator(Configuration configuration) {
    super(configuration);
  }

  /**
   * @param containerParseResult ASIC container parse result
   * @param configuration        configuration
   */
  public AsicSContainerValidator(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration);
  }

  /**
   * @param containerParseResult ASIC container parse result
   * @param configuration        configuration context
   * @param validateManifest     validate manifest
   */
  public AsicSContainerValidator(
          AsicParseResult containerParseResult, Configuration configuration, boolean validateManifest
  ) {
    super(containerParseResult, configuration, validateManifest);
  }

  @Override
  protected void validateSignatures(List<Signature> signatures) {
    if (containsMultipleSignatureFiles(signatures)) {
      DigiDoc4JException error = new DigiDoc4JException("ASICS container can only contain single signature file");
      errors.add(error);
    }
    super.validateSignatures(signatures);
  }

  @Override
  protected ArrayList<DigiDoc4JException> getListWithManifestMissingException() {
    return new ArrayList<>();
  }

  private boolean containsMultipleSignatureFiles(List<Signature> signatures) {
    Set<String> signatureFiles = new HashSet<>();
    for (Signature signature : signatures) {
      signatureFiles.add(((AsicSignature) signature).getSignatureDocument().getName());
    }
    return signatureFiles.size() > 1;
  }

}
