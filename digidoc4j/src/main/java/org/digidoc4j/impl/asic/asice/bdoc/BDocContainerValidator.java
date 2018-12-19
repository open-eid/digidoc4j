/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.asice.bdoc;

import java.io.Serializable;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.Signature;
import org.digidoc4j.impl.asic.AsicContainerValidationResult;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.asice.AsicEContainerValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BDOC container validator
 */
public class BDocContainerValidator extends AsicEContainerValidator implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainerValidator.class);

  /**
   * @param configuration configuration
   */
  public BDocContainerValidator(Configuration configuration) {
    super(configuration);
  }

  /**
   * @param containerParseResult ASIC container parse result
   * @param configuration        configuration
   */
  public BDocContainerValidator(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration);
  }

  /**
   * @param containerParseResult ASIC container parse result
   * @param configuration        configuration context
   * @param validateManifest     validate manifest
   */
  public BDocContainerValidator(AsicParseResult containerParseResult, Configuration configuration,
                                boolean validateManifest) {
    super(containerParseResult, configuration, validateManifest);
  }

  /**
   * @param signatures list of signatures
   * @return validation result
   */
  public ContainerValidationResult validate(List<Signature> signatures) {
    logger.debug("Validating BDOC container");
    validateSignatures(signatures);
    extractManifestErrors(signatures);
    AsicContainerValidationResult result = createValidationResult();
    logger.info("Is container valid: " + result.isValid());
    return result;
  }
}
