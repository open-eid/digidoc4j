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

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.asice.AsicEContainerValidator;

/**
 * BDOC container validator
 */
public class BDocContainerValidator extends AsicEContainerValidator {

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
}
