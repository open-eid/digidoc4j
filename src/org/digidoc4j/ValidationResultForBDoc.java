package org.digidoc4j;

import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import org.digidoc4j.api.ValidationResult;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Overview of errors and warnings for BDoc
 */

public class ValidationResultForBDoc implements ValidationResult {
  static final Logger logger = LoggerFactory.getLogger(ValidationResultForDDoc.class);
  private List<DigiDoc4JException> errors = new ArrayList<DigiDoc4JException>();
  private List<DigiDoc4JException> warnings = new ArrayList<DigiDoc4JException>();
  private String report;

  /**
   * Constructor
   *
   * @param validator add description
   */
  public ValidationResultForBDoc(SignedDocumentValidator validator) {
    logger.debug("");

    SimpleReport simpleReport = validator.getSimpleReport();

    List<String> signatureIds = simpleReport.getSignatureIds();

    for (String signatureId : signatureIds) {
      List<Conclusion.BasicInfo> results = simpleReport.getErrors(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation error: " + message);
        errors.add(new DigiDoc4JException(message));
      }
      results = simpleReport.getWarnings(signatureId);
      for (Conclusion.BasicInfo result : results) {
        String message = result.toString();
        logger.debug("Validation warning: " + message);
        warnings.add(new DigiDoc4JException(message));
      }
    }
    report = simpleReport.toString();
    logger.debug(report);
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
    return report;
  }
}
