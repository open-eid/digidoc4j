package org.digidoc4j;

import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.List;

/**
 * Validation result information.
 *
 * For BDOC the ValidationResult contains only information for the first signature of each signature XML file
 */
public interface ValidationResult {
  /**
   * Return a list of errors.
   * DDOC returns all validation results as errors.
   *
   * @return list of errors
   */
  List<DigiDoc4JException> getErrors();

  /**
   * Return a list of warnings.
   * DDOC always returns an empty list.
   *
   * @return list of warnings
   */
  List<DigiDoc4JException> getWarnings();

  /**
   * Are there any validation errors.
   *
   * @return value indicating if any errors exist
   */
  boolean hasErrors();

  /**
   * Are there any validation warnings.
   * DDOC always returns false.
   *
   * @return value indicating if any warnings exist
   */
  boolean hasWarnings();

  /**
   * @return true when document is valid
   */
  boolean isValid();

  /**
   * Get validation report.
   *
   * @return report
   */
  String getReport();
}
