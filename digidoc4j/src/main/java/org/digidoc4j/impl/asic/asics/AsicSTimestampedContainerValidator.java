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

import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.ContainerValidationResult;

import java.util.Objects;

/**
 * A validator for ASiC-S containers with timestamp tokens.
 */
public class AsicSTimestampedContainerValidator {

  private final AsicSContainer asicsContainer;

  /**
   * Creates an instance of a validator.
   *
   * @param asicsContainer ASiC-S container to validate
   */
  public AsicSTimestampedContainerValidator(AsicSContainer asicsContainer) {
    this.asicsContainer = Objects.requireNonNull(asicsContainer);
  }

  /**
   * Validate the current state of this validator and return an instance of {@link ContainerValidationResult}.
   *
   * @return container validation result
   */
  public ContainerValidationResult validate() {
    Reports reports = new AsicSTimestampsValidationReportGenerator(asicsContainer).openValidationReport();
    // TODO (DD4J-1074): build container validation result from validation reports
    return null;
  }

}
