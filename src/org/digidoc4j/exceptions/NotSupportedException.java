package org.digidoc4j.exceptions;

/**
 * Exception is thrown when not supported container configuration is created
 */
public class NotSupportedException extends DigiDoc4JException {

  /**
   * Creates exception
   *
   * @param message reason to throw exception
   */
  public NotSupportedException(String message) {
    super("Not supported: " + message);
  }
}
