package org.digidoc4j.api.exceptions;

/**
 * Exception is thrown when method or class is not yet implemented.
 */

public class NotYetImplementedException extends DigiDoc4JException {
  /**
   *
   */
  public NotYetImplementedException() {
    super("Not implemented yet");
  }

  /**
   * Not implemented yet exception with specific message
   *
   * @param message message
   */
  public NotYetImplementedException(String message) {
    super(message);
  }
}
