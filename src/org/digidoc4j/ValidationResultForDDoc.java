package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.api.ValidationResult;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Overview of errors and warnings for DDoc
 */
public class ValidationResultForDDoc implements ValidationResult {
  static final Logger logger = LoggerFactory.getLogger(ValidationResultForDDoc.class);
  private List<DigiDoc4JException> errors = new ArrayList<DigiDoc4JException>();
  private List<DigiDoc4JException> warnings = new ArrayList<DigiDoc4JException>();

  /**
   * Constructor
   *
   * @param documentFormat add description
   * @param exceptions add description
   */
  public ValidationResultForDDoc(String documentFormat, List<DigiDocException> exceptions) {
    logger.debug("");

    for (DigiDocException exception : exceptions) {
      String message = exception.getMessage();
      int code = exception.getCode();
      DigiDoc4JException digiDoc4JException = new DigiDoc4JException(code, message);
      if (isWarning(documentFormat, digiDoc4JException)) {
        logger.debug("Validation warning. Code: " + code + ", message: " + message);
        warnings.add(digiDoc4JException);
      } else {
        logger.debug("Validation error. Code: " + code + ", message: " + message);
        errors.add(digiDoc4JException);
      }
    }
  }

  static boolean isWarning(String documentFormat, DigiDoc4JException exception) {
    logger.debug("");
    int errorCode = exception.getErrorCode();
    return (errorCode == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
        || errorCode == DigiDocException.ERR_OLD_VER
        || errorCode == DigiDocException.ERR_TEST_SIGNATURE
        || errorCode == DigiDocException.WARN_WEAK_DIGEST
        || (errorCode == DigiDocException.ERR_ISSUER_XMLNS && !documentFormat.equals(SignedDoc.FORMAT_SK_XML)));
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    logger.debug("Returning " + errors.size() + " errors");
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    logger.debug("Returning " + warnings.size() + " warnings");
    return warnings;
  }

  @Override
  public boolean hasErrors() {
    boolean hasErrors = (errors.size() != 0);
    logger.debug("Has Errors: " + hasErrors);
    return hasErrors;
  }

  @Override
  public boolean hasWarnings() {
    boolean hasWarnings = (warnings.size() != 0);
    logger.debug("Has warnings: " + hasWarnings);
    return hasWarnings;
  }

  @Override
  public boolean isValid() {
    return !hasErrors();
  }
}
