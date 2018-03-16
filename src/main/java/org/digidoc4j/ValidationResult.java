package org.digidoc4j;

import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public interface ValidationResult {

  /**
   * @return true when document is valid
   */
  boolean isValid();

  /**
   * Are there any validation warnings.
   * DDOC always returns false.
   *
   * @return value indicating if any warnings exist
   */
  boolean hasWarnings();

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

}
