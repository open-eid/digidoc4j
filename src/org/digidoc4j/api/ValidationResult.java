package org.digidoc4j.api;

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
   * Constructor
   *
   * @param errors   List of validation errors
   * @param warnings List of validation warnings
   */
  public ValidationResult(List<DigiDoc4JException> errors, List<DigiDoc4JException> warnings) {
    this.errors = errors;
    this.warnings = warnings;
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


}
