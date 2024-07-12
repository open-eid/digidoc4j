/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.ValidationResult;

import java.util.Objects;

/**
 * An immutable encapsulation of timestamp validation data.
 */
public class TimestampValidationData {

  private final String timestampUniqueId;
  private final Reports encapsulatingReports;
  private final ValidationResult validationResult;
  // TODO (DD4J-1076): add timestamp qualification field/getter?

  /**
   * @param timestampUniqueId unique id / DSS id of the related timestamp
   * @param encapsulatingReports reports that encapsulate the validation results of the related timestamp
   * @param validationResult validation result of the related timestamp
   */
  public TimestampValidationData(String timestampUniqueId, Reports encapsulatingReports, ValidationResult validationResult) {
    this.timestampUniqueId = Objects.requireNonNull(timestampUniqueId);
    this.encapsulatingReports = Objects.requireNonNull(encapsulatingReports);
    this.validationResult = Objects.requireNonNull(validationResult);
  }

  /**
   * Returns the unique id / DSS id of the related timestamp.
   *
   * @return unique id / DSS id of the related timestamp
   */
  public String getTimestampUniqueId() {
    return timestampUniqueId;
  }

  /**
   * Returns the reports that encapsulate the validation results of the related timestamp.
   *
   * @return reports that encapsulate the validation results of the related timestamp
   */
  public Reports getEncapsulatingReports() {
    return encapsulatingReports;
  }

  /**
   * Returns validation result of the related timestamp.
   *
   * @return validation result of the related timestamp
   */
  public ValidationResult getValidationResult() {
    return validationResult;
  }

}
