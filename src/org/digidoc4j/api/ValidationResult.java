package org.digidoc4j.api;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Overview of errors and warnings
 */
public class ValidationResult {
  static final Logger logger = LoggerFactory.getLogger(ValidationResult.class);
  private List<DigiDoc4JException> errors = new ArrayList<DigiDoc4JException>();
  private List<DigiDoc4JException> warnings = new ArrayList<DigiDoc4JException>();


  /**
   * Add error
   *
   * @param error Digidoc4JException error
   */
  public void addError(DigiDoc4JException error) {
    logger.debug("");
    errors.add(error);
  }

  /**
   * Add warning
   *
   * @param warning Digidoc4JException warning
   */
  public void addWarning(DigiDoc4JException warning) {
    logger.debug("");
    warnings.add(warning);
  }

  /**
   * Return a list of errors
   *
   * @return list of Digidoc4JException errors
   */
  public List<DigiDoc4JException> getErrors() {
    logger.debug("Returning " + errors.size() + " errors");
    return errors;
  }

  /**
   * Return a list of warnings
   *
   * @return list of Digidoc4JException messages
   */
  public List<DigiDoc4JException> getWarnings() {
    logger.debug("Returning " + warnings.size() + " warnings");
    return warnings;
  }

  /**
   * Are there any validation errors.
   *
   * @return value indicating if any errors exist
   */
  public boolean hasErrors() {
    boolean hasErrors = (errors.size() != 0);
    logger.debug("Has Errors: " + hasErrors);
    return hasErrors;
  }

  /**
   * Are there any validation warnings.
   *
   * @return value indicating if any warnings exist
   */
  public boolean hasWarnings() {
    boolean hasWarnings = (warnings.size() != 0);
    logger.debug("Has warnings: " + hasWarnings);
    return hasWarnings;
  }

  /**
   * Generate validation result for DDoc
   *
   * @param document   Validated document
   * @param exceptions List of DigiDocExceptions found for the document
   * @return validation result
   */
  public static ValidationResult fromList(SignedDoc document, ArrayList<DigiDocException> exceptions) {
    logger.debug("");
    ValidationResult validationResult = new ValidationResult();
    for (ee.sk.digidoc.DigiDocException exception : exceptions) {
      DigiDoc4JException digiDoc4JException = new DigiDoc4JException(exception.getMessage());
      String message = exception.toString();
      if (isWarning(document, digiDoc4JException)) {
        logger.debug("Validation warning : " + message);
        validationResult.addWarning(new DigiDoc4JException(message));
      } else {
        logger.debug("Validation error : " + message);
        validationResult.addError(new DigiDoc4JException(message));
      }
    }
    return validationResult;
  }

  static boolean isWarning(SignedDoc document, DigiDoc4JException exception) {
    logger.debug("");
    int errorCode = exception.getErrorCode();
    return (errorCode == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
        || errorCode == DigiDocException.ERR_OLD_VER
        || errorCode == DigiDocException.ERR_TEST_SIGNATURE
        || errorCode == DigiDocException.WARN_WEAK_DIGEST
        || (errorCode == DigiDocException.ERR_ISSUER_XMLNS && !document.getFormat().equals(SignedDoc.FORMAT_SK_XML)));
  }
}
