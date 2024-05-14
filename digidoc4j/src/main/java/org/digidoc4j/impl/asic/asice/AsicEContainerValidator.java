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
import org.digidoc4j.impl.asic.AsicContainerValidator;
import org.digidoc4j.impl.asic.AsicParseResult;

/**
 * ASiC-E container validator
 */
public class AsicEContainerValidator extends AsicContainerValidator {

  /**
   * @param configuration configuration
   */
  public AsicEContainerValidator(Configuration configuration) {
    super(configuration);
  }

  /**
   * @param containerParseResult parse result
   * @param configuration        configuration
   */
  public AsicEContainerValidator(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration);
  }

  /**
   * @param containerParseResult parse result
   * @param configuration        configuration context
   * @param validateManifest     validate manifest
   */
  public AsicEContainerValidator(
          AsicParseResult containerParseResult, Configuration configuration, boolean validateManifest
  ) {
    super(containerParseResult, configuration, validateManifest);
  }

}
