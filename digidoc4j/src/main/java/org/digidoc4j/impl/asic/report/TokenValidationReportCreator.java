/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.report;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.List;
import java.util.Objects;

/**
 * Base class for token validation report creators
 */
class TokenValidationReportCreator {

  protected final Reports reports;
  protected final XmlSimpleReport simpleReport;

  protected TokenValidationReportCreator(Reports reports) {
    this.reports = Objects.requireNonNull(reports);
    this.simpleReport = reports.getSimpleReportJaxb();
  }

  /**
   * Complements validation report with errors and warnings which are
   * present in validation result but missing from validation report.
   *
   * @param validationResult the source of all errors and warnings
   * @param validationReport the destination to add missing errors and warnings to
   */
  protected static void updateMissingErrorsAndWarnings(ValidationResult validationResult, TokenValidationReport validationReport) {
    List<String> errors = validationReport.getErrors();
    for (DigiDoc4JException error : validationResult.getErrors()) {
      if (!errors.contains(error.getMessage())) {
        errors.add(error.getMessage());
      }
    }
    List<String> warnings = validationReport.getWarnings();
    for (DigiDoc4JException warning : validationResult.getWarnings()) {
      if (!warnings.contains(warning.getMessage())) {
        warnings.add(warning.getMessage());
      }
    }
  }

}
