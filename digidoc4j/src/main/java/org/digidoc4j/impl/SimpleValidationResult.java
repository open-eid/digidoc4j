package org.digidoc4j.impl;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class SimpleValidationResult extends AbstractValidationResult {

  private final String validationName;

  /**
   * @param validationName name of validation result
   */
  public SimpleValidationResult(String validationName) {
    this.validationName = validationName;
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return this.validationName;
  }

}
