/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;

/**
 * Overview of errors and warnings for BDoc
 */

public class ValidationResultForBDoc implements ValidationResult {
  private final static Logger logger = LoggerFactory.getLogger(ValidationResultForBDoc.class);
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private List<DigiDoc4JException> manifestValidationExceptions = new ArrayList<>();
  private BDocValidationReportBuilder reportBuilder;

  /**
   * Constructor
   *
   * @param report                       creates validation result from report
   * @param signatures                   list of signatures
   * @param manifestErrors               manifest verification errors
   * @param additionalVerificationErrors digidoc4J additional verification errors
   */
  public ValidationResultForBDoc(Reports report, Collection<Signature> signatures, List<String> manifestErrors,
                                 Map<String, List<DigiDoc4JException>> additionalVerificationErrors) {
    logger.debug("");
    reportBuilder = new BDocValidationReportBuilder(report, manifestErrors, additionalVerificationErrors);

    for (String manifestError : manifestErrors) {
      manifestValidationExceptions.add(new DigiDoc4JException(manifestError));
    }
    if (manifestValidationExceptions.size() != 0) errors.addAll(manifestValidationExceptions);

    for (Signature signature : signatures) {
      List<DigiDoc4JException> signatureValidationResult = signature.validate();

      if (signatureValidationResult.size() != 0) {
        errors.addAll(signatureValidationResult);
      }
    }

    do {
      SimpleReport simpleReport = report.getSimpleReport();

      //check with several signatures as well in one signature file (in estonia we are not producing such signatures)
      String signatureId = simpleReport.getSignatureIdList().get(0);

      List<Conclusion.BasicInfo> results = simpleReport.getWarnings(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation warning: " + message);
        warnings.add(new DigiDoc4JException(message));
      }
      if (logger.isDebugEnabled()) {
        logger.debug(simpleReport.toString());
      }

      report = report.getNextReports();
    } while (report != null);
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  @Override
  public boolean hasErrors() {
    return (errors.size() != 0);
  }

  @Override
  public boolean hasWarnings() {
    return (warnings.size() != 0);
  }

  @Override
  public boolean isValid() {
    return !hasErrors();
  }

  @Override
  public String getReport() {
    return reportBuilder.buildXmlReport();
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return manifestValidationExceptions;
  }
}
