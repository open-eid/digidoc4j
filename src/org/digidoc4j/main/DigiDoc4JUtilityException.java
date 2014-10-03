package org.digidoc4j.main;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Exceptions thrown by DigiDoc4JUtility
 */
public class DigiDoc4JUtilityException extends DigiDoc4JException {
  private final int errorCode;

  /**
   * Throws exception with error code and message
   *
   * @param errorCode error code
   * @param message   error message
   */
  public DigiDoc4JUtilityException(int errorCode, String message) {
    super("DigiDoc4J utility - " + message + "\n");
    this.errorCode = errorCode;
  }

  /**
   * Returns error code
   * @return error code
   */
  public int getErrorCode() {
    return errorCode;
  }
}
